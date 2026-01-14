// ==================================================================
// External Dependencies
import * as path from "path";
import { createServer } from "http";
import { WebSocketServer } from "ws";
import express from "express";
import * as bodyParser from "body-parser";
import { config } from "dotenv";

// ==================================================================
// User-Defined Modules
import "./misc/loggerpatch";
import * as EVENTS from "../static/js/configs/events.json";
import * as MessageConfig from "../static/js/configs/messageConfig.json";
import CONFIG from "./config";
import ratelimiter from "./modules/ratelimiter";
import { AccessTokensManager, AccountManager, AccountInstance } from "./modules/accounts";
import { RoomsManager } from "./modules/room";
import { WebSocketConnectedClient, Room } from "./modules/room";
import { Attachment, UpdateInstance } from "./modules/messages";
// Validating Schemas
import * as apiSchema from "./schemas/api";

// ==================================================================
// Init
// ==================================================================

// load .env into SECRETS object and not process.env
const SECRETS: Record<string, string> = {};
config({ debug: false, processEnv: SECRETS });
let isDemoMode = false;
if (SECRETS.IS_DEMO_WEB === "1") {
    console.log(">> DEMO MODE IS ENABLED. Disabling signups");
    isDemoMode = true;
}

// Data store: access tokens, accounts
const ACCOUNTS = new AccountManager();
const ACCOUNT_TOKENS = new AccessTokensManager(CONFIG.storedFiles.accessTokens, CONFIG.access_token_expire_interval);
const Rooms = new RoomsManager();

// simple cookie reader
function readCookies(cookiesStr: string): Record<string, string> {
    let cookies: any = false;
    try {
        cookies = cookiesStr.split(";");
        cookies = cookies.map((e: string) => e.split("="));
        cookies = Object.fromEntries(cookies);
    } catch {
        cookies = false;
    }
    if (typeof cookies === "object") {
        return cookies;
    } else {
        return {};
    }
}

// ==================================================================
// Main 
// ==================================================================

const app = express();
const server = createServer(app);
const wss = new WebSocketServer({ server, path: "/api/ws" });

// short one-liner func to "reply" to express requests with stringified json
const express_reply = (res: any, data: {}) => res.send(JSON.stringify(data));

// WIP (unimplemented): ratelimiting to prevent DOS / DDOS
app.use(ratelimiter);

// POST request handling
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.text())

// static files
app.use(express.static(path.join(__dirname, "../static")));

function safeParseJSON(text: string) {
    let ret: false | Record<string, any> = false;
    try {
        ret = JSON.parse(text);
    } catch (error) { }
    return ret;
}

// login & signup
app.post("/api/signup", async (req, res) => {
    const message = safeParseJSON(req.body);
    if (!message) {
        return express_reply(res, {
            error: true,
            message: "Invalid post body"
        });
    }

    if (isDemoMode || !CONFIG.accepting_new_registrations) {
        console.log(req.ip + " >> tried to register with username [" + (typeof message.username === "string" ? message.username : "<invalid username>") + "] but failed.");
        return express_reply(res, {
            error: true,
            message: "Signups are closed. Please try again later."
        });
    }

    const validated = apiSchema.signupRequest.safeParse(message);
    if (validated.error) {
        return express_reply(res, {
            error: true,
            message: "Invalid credentials provided."
        });
    }

    const { username, password } = validated.data;

    const account = ACCOUNTS.get(username);
    if (account) {
        return express_reply(res, {
            error: true,
            message: "Account already exists"
        });
    }

    const createAccResult = await ACCOUNTS.set(username, password);
    if (!createAccResult) {
        return express_reply(res, {
            error: true,
            message: "Unknown error while creating account, please contact developer"
        });
    }

    const response = ACCOUNT_TOKENS.createAccessToken(username);
    res.cookie(
        "accessToken",
        response,
        { maxAge: CONFIG.access_token_expire_interval }
    ).send(JSON.stringify({ error: false }));
})

app.post("/api/login", async (req, res) => {
    const message = safeParseJSON(req.body);
    if (!message) {
        return express_reply(res, {
            error: true,
            message: "Invalid post body"
        });
    }

    const validated = apiSchema.loginRequest.safeParse(message);
    if (validated.error) {
        return express_reply(res, {
            error: true,
            message: "Invalid credentials provided."
        });
    }

    const { username, password } = validated.data;

    const account = ACCOUNTS.get(username);
    if (!account) {
        return express_reply(res, {
            error: true,
            message: "Account does not exist!"
        });
    }

    if (!(await ACCOUNTS.validatePassword(username, password))) {
        return express_reply(res, {
            error: true,
            message: "Incorrect password!"
        });
    }

    const token = ACCOUNT_TOKENS.createAccessToken(username);
    res.cookie(
        "accessToken",
        token,
        { maxAge: CONFIG.access_token_expire_interval }
    ).send(JSON.stringify({ error: false }));
})

app.get("/api/logout", (req, res) => {
    const cookies = readCookies(req.headers.cookie || "");
    const validated = apiSchema.logoutRequest.safeParse({ ...req.query, accessToken: cookies.accessToken });
    if (validated.error) {
        return express_reply(res, {
            error: true,
            message: "Invalid credentials provided."
        });
    }

    const { username, accessToken } = validated.data;

    if (!(ACCOUNTS.exists(username))) {
        return express_reply(res, {
            error: true,
            message: "Invalid Access Token / Username"
        });
    }

    const tokenValidity = ACCOUNT_TOKENS.validateAccessToken(username, accessToken);
    if (tokenValidity !== "valid") {
        return express_reply(res, {
            error: true,
            message: "Token Status: " + tokenValidity
        });
    }

    const result = ACCOUNT_TOKENS.deleteAccessToken(username);
    if (!result) {
        return express_reply(res, {
            error: true,
            message: "Could not delete access token"
        });
    }

    express_reply(res, {
        error: false
    });
})

app.get("/api/account", (req, res) => {
    const cookies = readCookies(req.headers.cookie || "");
    const validated = apiSchema.accountRequest.safeParse({ ...req.query, accessToken: cookies.accessToken });
    if (validated.error) {
        return express_reply(res, {
            error: true,
            message: "Invalid credentials provided."
        });
    }

    const { username, accessToken } = validated.data;

    if (!(ACCOUNTS.exists(username))) {
        return express_reply(res, {
            error: true,
            message: "Invalid Access Token / Username"
        });
    }

    const tokenValidity = ACCOUNT_TOKENS.validateAccessToken(username, accessToken);
    if (tokenValidity !== "valid") {
        return express_reply(res, {
            error: true,
            message: "Token Status: " + tokenValidity
        });
    }

    express_reply(res, {
        error: false,
        data: {
            ...ACCOUNTS.get(username),
            ip: req.ip,
            username
        }
    });
})

app.get("/api/create_room", (req, res) => {
    const cookies = readCookies(req.headers.cookie || "");
    const validated = apiSchema.createRoomRequest.safeParse({ ...req.query, accessToken: cookies.accessToken });
    if (validated.error) {
        return express_reply(res, {
            error: true,
            message: "Invalid credentials provided."
        });
    }

    const { username: creator, password, accessToken } = validated.data;

    if (!(ACCOUNTS.exists(creator))) {
        return express_reply(res, {
            error: true,
            message: "Invalid Username"
        });
    }

    const tokenValidity = ACCOUNT_TOKENS.validateAccessToken(creator, accessToken);
    if (tokenValidity !== "valid") {
        return express_reply(res, {
            error: true,
            message: "Token Status: " + tokenValidity
        });
    }

    const rid = Rooms.createRoom(
        password.length > CONFIG.min_room_password_length ? password : false,
        creator,
        (endpoint, dirpath) => {
            app.use(endpoint, express.static(dirpath));
        }
    );

    express_reply(res, {
        id: rid,
        error: false
    });
})

app.get("/api/destroy_room", (req, res) => {
    const cookies = readCookies(req.headers.cookie || "");
    const validated = apiSchema.destroyRoomRequest.safeParse({ ...req.query, accessToken: cookies.accessToken });
    if (validated.error) {
        return express_reply(res, {
            error: true,
            message: "Invalid credentials provided."
        });
    }

    const { accessToken, username, rid } = validated.data;

    if (!(ACCOUNTS.exists(username))) {
        return express_reply(res, {
            error: true,
            message: "Invalid Username"
        });
    }
    const requestSendorAccount = ACCOUNTS.get(username);

    const tokenValidity = ACCOUNT_TOKENS.validateAccessToken(username, accessToken);
    if (tokenValidity !== "valid") {
        return express_reply(res, {
            error: true,
            message: "Token Status: " + tokenValidity
        });
    }

    const room = Rooms.getRoom(rid);
    if (!room) {
        return express_reply(res, {
            error: true,
            message: "Room 404"
        });
    }

    if (!(room.creator === username || requestSendorAccount.isAdmin)) {
        return express_reply(res, {
            error: true,
            message: "Unauthorized"
        });
    }

    const destroyed = Rooms.destroyRoom(rid);
    if (!destroyed) {
        return express_reply(res, {
            error: true,
            message: "Unknown Error. Could not destroy room"
        });
    }

    return express_reply(res, {
        error: false
    });
})

// WebSocket connection handler
wss.on("connection", (ws: WebSocketConnectedClient, req) => {
    let msgCount = 0;
    const msgInterval = setInterval(() => {
        msgCount = 0;
    }, 1000);

    // small one liner to send JSON data to the connected client
    const send = (label: string, data: {} = {}) => { try { ws.send(JSON.stringify([label, data])) } catch (e) { console.log("WebSocket send err:", e) } };
    const close_ws = (reason: string) => {
        try {
            try {
                ws.sendJSON(EVENTS.WS_CLOSE, { message: reason });
            } catch (e) { }
            ws.close();
        } catch (e) { }
    };
    Object.defineProperty(ws, "sendJSON", { value: send, writable: false, configurable: false });

    const cookies = readCookies(req.headers.cookie || "");

    let forceClosed = false;
    let closeReason = "unknown error";
    let hasPinged = true;
    let pingInterval = setInterval(() => {
        if (hasPinged) {
            hasPinged = false;
            send(EVENTS.PING);
        } else {
            try {
                closeReason = "did not respond to pings";
                forceClosed = true;
                close_ws(closeReason);
            } catch { };
        }
    }, CONFIG.ws_ping_timeout);

    // client info
    let loggedInAccount: AccountInstance;
    let isLoggedIn = false;
    let username: string;
    let inRoom = false;
    let room: Room;

    let loginTimeout = setTimeout(() => {
        if (!isLoggedIn) {
            forceClosed = true;
            closeReason = "client did not login";
            close_ws(closeReason);
        }
    }, 5e3);

    ws.on("close", () => {
        clearInterval(msgInterval);

        try {
            clearInterval(pingInterval);
        } catch { }

        if (forceClosed) {
            console.log("WebSocket was forcefully closed with reason: " + closeReason);
        }

        if (inRoom) {
            room.removeClient(username);
            inRoom = false;
        }
    })

    ws.on("message", (rawdata) => {
        msgCount++;
        if (msgCount > 20) {
            forceClosed = true;
            closeReason = "rate limit exceeded";
            close_ws(closeReason);
            return;
        }

        let pkt: [string, Record<string, any>];
        try {
            const rawpktdata = rawdata.toString();
            const rawpktsize = new TextEncoder()
                .encode(rawpktdata)
                .byteLength;
            if (rawpktsize > MessageConfig.maxMessagePacketByteLength) throw "message packet length exceeded";
            pkt = JSON.parse(rawpktdata);
            if (!(Array.isArray(pkt) && pkt.length > 0)) throw "invalid data format";
        } catch (error) {
            closeReason = "malformed data provided";
            forceClosed = true;
            send(EVENTS.SHOW_ALERT, {
                message: closeReason
            });
            close_ws(closeReason);
            return;
        }

        if (forceClosed) return;

        const [label, data] = pkt;

        if (label === EVENTS.PING) {
            hasPinged = true;
            return;
        }
        if (isLoggedIn) {
            // only logged in
            switch (label) {

                case EVENTS.ROOM:
                    if (
                        typeof data.rid === "string" &&
                        data.rid.length > 0
                    ) {
                        if (inRoom) {
                            room.removeClient(username);
                            inRoom = false;
                            room = {} as Room;
                        }
                        const roomInstance = Rooms.getRoom(data.rid);
                        if (roomInstance) {
                            const addToRoom = () => {
                                roomInstance.addClient(username, ws, ACCOUNTS);
                                send(roomInstance.lastUpdate.label, roomInstance.lastUpdate);
                                inRoom = true;
                                room = roomInstance;
                            }
                            if (typeof roomInstance.password === "string") {
                                if (
                                    (
                                        typeof data.password === "string" &&
                                        roomInstance.password === data.password
                                    ) ||
                                    username === roomInstance.creator
                                ) {
                                    addToRoom();
                                } else {
                                    closeReason = "Invalid Room Password";
                                    forceClosed = true;
                                }
                            } else {
                                addToRoom();
                            }
                        } else {
                            closeReason = "Room 404";
                            forceClosed = true;
                        }
                    } else {
                        closeReason = "invalid room id provided";
                        forceClosed = true;
                    }
                    break;

            }

            if (inRoom) {
                // logged in and in room
                switch (label) {

                    case EVENTS.MESSAGE_NEW:
                        let { attachments, content } = data;
                        const parsedAttachments: Attachment[] = [];
                        let done = false;

                        if (
                            !(
                                content &&
                                content.length > 0 &&
                                content.length <= MessageConfig.textLimit
                            )
                        ) {
                            send(EVENTS.SHOW_ALERT, {
                                message: "invalid message sent"
                            });
                            done = true;
                        }

                        if (
                            attachments &&
                            Array.isArray(attachments) &&
                            attachments.length <= MessageConfig.attachmentsLimit
                        ) {
                            let failedChecks = false;
                            let failedAttachments: string[] = [];

                            const validateAttachmentFilename = (filename: string) => {
                                let final = "";
                                const allowed = /[a-z|A-Z|0-9|_|-|.]+$/;
                                for (const char of filename) {
                                    if (allowed.test(char)) {
                                        final += char;
                                    }
                                }
                                return final;
                            }

                            for (let i = 0; i < attachments.length; i++) {
                                const item = attachments[i];
                                item.filename = typeof item.filename === "string" ? item.filename : "";
                                item.filename = validateAttachmentFilename(item.filename);
                                if (
                                    Object.keys(item).length === 2 &&
                                    item.filename.length <= MessageConfig.attachmentFilenameLimit &&
                                    item.filename.length > 1 &&
                                    typeof item.data === "string" &&
                                    item.data.length <= MessageConfig.maxfileByteLength
                                ) {
                                    try {
                                        item.data = Buffer.from(item.data, "base64");
                                        parsedAttachments.push(item);
                                    } catch (e) {
                                        item.data = null;
                                        attachments[i] = null;
                                        failedAttachments.push(item.filename);
                                    }
                                } else {
                                    attachments = null;
                                    failedChecks = true;
                                    break;
                                }
                            }
                            if (failedChecks) {
                                send(EVENTS.SHOW_ALERT, {
                                    message: "invalid attachment(s)"
                                });
                                done = true;
                            }
                            if (failedAttachments.length > 0) {
                                send(EVENTS.SHOW_ALERT, {
                                    message: "The following attachments could not be sent:" + failedAttachments.join(", ")
                                });
                            }
                        }

                        if (!done) {
                            room.addMessage(username, content, parsedAttachments);
                        }
                        break;

                        case EVENTS.VOICE_JOIN:
                        // Tell everyone else I joined voice
                        room.broadcastUpdate(new UpdateInstance(EVENTS.VOICE_JOIN, { username }), username);
                        break;

                    case EVENTS.VOICE_LEAVE:
                        // Tell everyone else I left voice
                        room.broadcastUpdate(new UpdateInstance(EVENTS.VOICE_LEAVE, { username }), username);
                        break;

                    case EVENTS.VOICE_SIGNAL:
                        // Route a signal (like "Hello, I want to call") to a specific person
                        if (data.target && typeof data.target === "string" && data.signal) {
                            room.sendDirect(data.target, EVENTS.VOICE_SIGNAL, {
                                sender: username,
                                signal: data.signal
                            });
                        }
                        break;

                }
            } else {
                // logged in but not in room
                switch (label) {
                    default:
                        break;
                }
            }
        } else {
            // not logged in
            switch (label) {

                case EVENTS.LOGIN:
                    if (
                        typeof data.username === "string" &&
                        data.username.length >= CONFIG.min_username_length &&
                        data.username.length <= CONFIG.max_username_length &&
                        ACCOUNTS.get(data.username) &&
                        typeof cookies.accessToken === "string" &&
                        cookies.accessToken.length > 0
                    ) {
                        const validity = ACCOUNT_TOKENS.validateAccessToken(data.username, cookies.accessToken);
                        if (validity === "valid") {
                            clearTimeout(loginTimeout);
                            loggedInAccount = ACCOUNTS.get(data.username);
                            username = data.username;
                            isLoggedIn = true;
                            console.log("[LOG] " + username + " > logged in");
                        } else {
                            closeReason = "accessToken Status: " + validity;
                            forceClosed = true;
                        }
                    } else {
                        closeReason = "invalid username/accessToken provided";
                        forceClosed = true;
                    }
                    break;

            }
        }

        if (forceClosed) {
            send(EVENTS.SHOW_ALERT, {
                message: closeReason
            });
            close_ws(closeReason);
        }
    })
})

// Start the server
server.listen(CONFIG.server_port, '0.0.0.0', () => {
    console.log("\t Server listening on PORT:", CONFIG.server_port);
    console.log(`\t Access at http://127.0.0.1:${CONFIG.server_port}\n`);
})
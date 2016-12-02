extern crate mio;
extern crate http_muncher;
extern crate sha1;
extern crate rustc_serialize;
extern crate byteorder;

mod frame;

use frame::*;

use rustc_serialize::base64::{ToBase64, STANDARD};
use http_muncher::{Parser, ParserHandler};
use mio::*;
use std::net::SocketAddr;
use mio::tcp::*;
use std::collections::HashMap;
use std::cell::RefCell;
use std::rc::Rc;
use std::fmt;


const SERVER_TOKEN: Token = Token(0);


enum ClientState {
    AwaitingHandshake(RefCell<Parser<HttpParser>>),
    HandshakeResponse,
    Connected,
}

fn gen_key(key: &String) -> String {
    let mut m = sha1::Sha1::new();
    let mut buf = [0u8; 20];
    m.update(key.as_bytes());
    m.update("258EAFA5-E914-47DA-95CA-C5AB0DC85B11".as_bytes());
    m.output(&mut buf);
    return buf.to_base64(STANDARD);
}

struct HttpParser {
    current_key: Option<String>,
    headers: Rc<RefCell<HashMap<String, String>>>,
}


impl ParserHandler for HttpParser {
    fn on_header_field(&mut self, s: &[u8]) -> bool {
        self.current_key = Some(std::str::from_utf8(s).unwrap().to_string());
        true
    }

    fn on_header_value(&mut self, s: &[u8]) -> bool {
        self.headers
            .borrow_mut()
            .insert(self.current_key.clone().unwrap(),
                    std::str::from_utf8(s).unwrap().to_string());
        true
    }

    fn on_headers_complete(&mut self) -> bool {
        false
    }
}

struct WebSocketClient {
    socket: TcpStream,
    headers: Rc<RefCell<HashMap<String, String>>>,
    interest: EventSet,
    state: ClientState,
    outgoing: Vec<WebSocketFrame>,
}

struct WebSocketServer {
    socket: TcpListener,
    clients: HashMap<Token, WebSocketClient>,
    token_counter: usize,
}

impl WebSocketClient {
    fn read_handshake(&mut self) {
        loop {
            let mut buf = [0; 2048];
            match self.socket.try_read(&mut buf) {
                Err(e) => {
                    println!("Error while reading socket: {:?}", e);
                    return;
                }
                Ok(None) => break,
                Ok(Some(_)) => {
                    let is_upgrade = if let ClientState::AwaitingHandshake(ref parser_state) =
                        self.state {
                        let mut parser = parser_state.borrow_mut();
                        parser.parse(&buf);
                        parser.is_upgrade()
                    } else {
                        false
                    };
                    if is_upgrade {
                        self.state = ClientState::HandshakeResponse;
                        self.interest.remove(EventSet::readable());
                        self.interest.insert(EventSet::writable());
                        break;
                    }
                }
            }
        }
    }

    pub fn read(&mut self) {
        match self.state {
            ClientState::AwaitingHandshake(_) => self.read_handshake(),
            ClientState::Connected => self.read_frame(),
            ClientState::HandshakeResponse => {}
        }
    }

    fn write(&mut self) {
        match self.state {
            ClientState::HandshakeResponse => self.write_handshake(),
            ClientState::Connected => {
                let mut close_connection = false;

                println!("sending {} frames", self.outgoing.len());

                for frame in self.outgoing.iter() {
                    if let Err(e) = frame.write(&mut self.socket) {
                        println!("error on write: {}", e);
                    }

                    if frame.is_close() {
                        close_connection = true;
                    }
                }

                self.outgoing.clear();

                self.interest.remove(EventSet::writable());

                if close_connection {
                    self.interest.insert(EventSet::hup());
                } else {
                    self.interest.insert(EventSet::readable());
                }
            }
            _ => {}
        }
    }

    fn read_frame(&mut self) {
        let frame = WebSocketFrame::read(&mut self.socket);
        match frame {
            Ok(frame) => {
                match frame.get_opcode() {
                    OpCode::TextFrame => {
                        println!("{:?}", frame);
                        let reply_frame = WebSocketFrame::from("Hi there!!");
                        self.outgoing.push(reply_frame);
                    }
                    OpCode::Ping => {
                        println!("ping/pong");
                        self.outgoing.push(WebSocketFrame::pong(&frame));
                    }
                    OpCode::ConnectionClose => {
                        println!("disconnecting client ... {:?}", frame);
                        self.outgoing.push(WebSocketFrame::close_from(&frame));
                    }
                    _ => {}
                }
                self.interest.remove(EventSet::readable());
                self.interest.insert(EventSet::writable());
            }
            Err(e) => println!("error while reading frame: {}", e),
        }
    }

    fn write_handshake(&mut self) {
        let headers = self.headers.borrow();
        let response_key = gen_key(&headers.get("Sec-WebSocket-Key").unwrap());
        let response = fmt::format(format_args!("HTTP/1.1 101 Switching \
                                                 Protocols\r\nConnection: \
                                                 Upgrade\r\nSec-WebSocket-Accept: \
                                                 {}\r\nUpgrade: websocket\r\n\r\n",
                                                response_key));
        self.socket.try_write(response.as_bytes()).unwrap();
        self.state = ClientState::Connected;
        self.interest.remove(EventSet::writable());
        self.interest.insert(EventSet::readable());
    }

    fn new(socket: TcpStream) -> WebSocketClient {
        let headers = Rc::new(RefCell::new(HashMap::new()));

        WebSocketClient {
            socket: socket,
            headers: headers.clone(),
            interest: EventSet::readable(),
            state: ClientState::AwaitingHandshake(RefCell::new(Parser::request(HttpParser {
                current_key: None,
                headers: headers.clone(),
            }))),
            outgoing: Vec::new(),
        }
    }
}

impl Handler for WebSocketServer {
    type Timeout = usize;
    type Message = ();

    fn ready(&mut self,
             event_loop: &mut EventLoop<WebSocketServer>,
             token: Token,
             events: EventSet) {
        if events.is_readable() {
            match token {
                SERVER_TOKEN => {
                    let client_socket = match self.socket.accept() {
                        Err(e) => {
                            println!("Accept error: {}", e);
                            return;
                        }
                        Ok(None) => unreachable!("Accept has returned 'None'"),
                        Ok(Some((sock, _))) => sock,
                    };
                    self.token_counter += 1;
                    let new_token = Token(self.token_counter);
                    self.clients.insert(new_token, WebSocketClient::new(client_socket));
                    event_loop.register(&self.clients[&new_token].socket,
                                  new_token,
                                  EventSet::readable(),
                                  PollOpt::edge() | PollOpt::oneshot())
                        .unwrap();
                }
                token => {
                    let mut client = self.clients.get_mut(&token).unwrap();
                    client.read();
                    event_loop.reregister(&client.socket,
                                    token,
                                    client.interest,
                                    PollOpt::edge() | PollOpt::oneshot())
                        .unwrap();
                }
            }
        }

        if events.is_writable() {
            let mut client = self.clients.get_mut(&token).unwrap();
            client.write();
            event_loop.reregister(&client.socket,
                            token,
                            client.interest,
                            PollOpt::edge() | PollOpt::oneshot())
                .unwrap();
        }

        if events.is_hup() {
            let client = self.clients.remove(&token).unwrap();
            client.socket.shutdown(Shutdown::Both);
            event_loop.deregister(&client.socket);
        }
    }
}

fn main() {
    let address = "0.0.0.0:10000".parse::<SocketAddr>().unwrap();
    let server_socket = TcpListener::bind(&address).unwrap();
    let mut event_loop = EventLoop::new().unwrap();

    let mut server = WebSocketServer {
        token_counter: 1,
        clients: HashMap::new(),
        socket: server_socket,
    };

    event_loop.register(&server.socket,
                  SERVER_TOKEN,
                  EventSet::readable(),
                  PollOpt::edge())
        .unwrap();

    event_loop.run(&mut server).unwrap();
}

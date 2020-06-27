pub struct MessagePipe<WS> {
    ws: WS,
}

impl<WS> MessagePipe<WS> {
    pub fn from_socket(ws: WS) -> Self { MessagePipe { ws } }
}

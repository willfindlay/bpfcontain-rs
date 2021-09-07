pub trait PubSub {
    type Metadata;
}

pub struct PubSubImpl;
impl PubSub for PubSubImpl {
    type Metadata = u32;
}

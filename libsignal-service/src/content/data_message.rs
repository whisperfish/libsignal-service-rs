use super::DataMessage;

impl DataMessage {
    pub fn is_story_reaction(&self) -> bool {
        self.has_story_context() && self.is_reaction()
    }

    pub fn is_reaction(&self) -> bool {
        self.reaction.is_some()
    }

    pub fn has_story_context(&self) -> bool {
        self.story_context.is_some()
    }
}

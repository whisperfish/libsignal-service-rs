use crate::proto::story_message::Attachment;

use super::StoryMessage;

impl StoryMessage {
    pub fn has_text_attachment(&self) -> bool {
        matches!(self.attachment, Some(Attachment::TextAttachment(_)))
    }

    pub fn has_file_attachment(&self) -> bool {
        matches!(self.attachment, Some(Attachment::FileAttachment(_)))
    }
}

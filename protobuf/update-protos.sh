#!/bin/bash
set -euo pipefail

update_proto() {
	case "$1" in
	  Signal-Android)
	  	git_revision="ba79a3e83e8dee71a33c0cc846809d5b648c2c88"
		prefix="libsignal-service/src/main/protowire/";;
	  Signal-Desktop)
	  	git_revision="82694f19260a5eee4a29dfbe83e4c64c78694e65"
		prefix="protos/";;
	esac
	curl -LOf https://raw.githubusercontent.com/signalapp/${1}/${git_revision}/${prefix}${2}
}

update_proto Signal-Android Groups.proto
update_proto Signal-Android Provisioning.proto
update_proto Signal-Android SignalService.proto
update_proto Signal-Android StickerResources.proto
update_proto Signal-Android WebSocketResources.proto

update_proto Signal-Desktop DeviceName.proto
update_proto Signal-Desktop UnidentifiedDelivery.proto

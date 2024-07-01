#!/bin/bash
set -euo pipefail

update_proto() {
	case "$1" in
	  Signal-Android)
	  	git_revision="251cec5dee06d8d36f0177967d675e8eac2ba32f"
		prefix="libsignal-service/src/main/protowire/";;
	  Signal-Desktop)
	  	git_revision="f46872b6e980132e8045b3288eb88d803f365a10"
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

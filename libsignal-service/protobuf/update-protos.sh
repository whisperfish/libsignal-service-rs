#!/bin/bash
set -euo pipefail

update_proto() {
	case "$1" in
	  Signal-Android) 
	  	git_revision="0cdd56e0accfe59e39a312f32bb1463f551dee33"
		prefix="libsignal/service/src/main/protowire/";;
	  Signal-Desktop)
	  	git_revision="0e194975a23669263d053b03a42ac52ad38c5d87"
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
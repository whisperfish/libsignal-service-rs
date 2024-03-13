#!/bin/bash
set -euo pipefail

update_proto() {
	case "$1" in
	  Signal-Android) 
	  	git_revision="940cee0f30d6a2873ae08c65bb821c34302ccf5d"
		prefix="libsignal-service/src/main/protowire/";;
	  Signal-Desktop)
	  	git_revision="70858d9063446b07b19c03ae7d0c01075a2849e3"
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

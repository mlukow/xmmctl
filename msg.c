/*	$OpenBSD$	*/
/*
 * Copyright (c) 2020 genua GmbH
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <endian.h>

#include "msg.h"

int
xmm_msg_add_header(struct asn1_buf *buf, enum xmm_7360_call_ids cmd,
    int async)
{
	struct asn1_buf_cp cp = asn1_buf_checkpoint(buf);
	uint32_t tid = 0x11000100U;
	uint32_t len;
	int ret;

	if (async) {
		tid |= 1U;
		ret = asn1_add_int32(buf, tid);
		if (ret != 0)
			goto err;
	}
	ret = asn1_add_raw_u32(buf, htobe32(tid));
	if (ret != 0)
		goto err;
	ret = asn1_add_int32(buf, cmd);
	if (ret != 0)
		goto err;

	len = asn1_buf_len(buf) + 6;
	ret = EINVAL;
	if (len > INT32_MAX)
		goto err;
	ret = asn1_add_int32(buf, len);
	if (ret != 0)
		goto err;
	if (asn1_buf_len(buf) != len)
		goto err;
	ret = asn1_add_raw_u32(buf, len);
	if (ret != 0)
		goto err;

	return 0;

err:
	asn1_buf_rollback(buf, cp);

	return ret;
}

int
xmm_msg_decode(struct asn1_buf *buf, struct xmm_msg *msg)
{
	struct asn1_buf_cp cp = asn1_buf_checkpoint(buf);
	int ret = EINVAL;
	uint32_t len;
	size_t aval = 0;
	struct asn1_val *n, val;

	msg->buf = 0;
	msg->code = 0;
	msg->txid = 0;
	msg->nval = 0;
	msg->val = NULL;

	ret = asn1_decode_raw_u32(buf, &len);
	if (ret != 0)
		goto err;
	ret = EINVAL;
	if (len != asn1_buf_len(buf))
		goto err;
	ret = asn1_decode_one(buf, &val);
	if (ret != 0)
		goto err;
	ret = EINVAL;
	if (!asn1_val_is_int(&val) || val.i < 0 || val.i != len)
		goto err;
	ret = asn1_decode_one(buf, &val);
	if (ret != 0)
		goto err;
	ret = EINVAL;
	if (!asn1_val_is_int(&val) || val.i < 0)
		goto err;
	msg->code = val.i;
	ret = asn1_decode_raw_u32(buf, &msg->txid);
	if (ret != 0)
		goto err;
	msg->txid = htobe32(msg->txid);
	if ((msg->txid & 0xffffff00U) == 0x11000100U
	    && msg->txid != 0x11000100U
	    && msg->code < 2000) {
		ret = asn1_decode_one(buf, &val);
		if (ret != 0)
			goto err;
		ret = EINVAL;
		if (!asn1_val_is_int(&val) || val.i != msg->txid)
			goto err;
	}

	aval = 0;
	while (asn1_buf_len(buf)) {
		if (msg->nval >= aval) {
			aval += 16;
			n = malloc(aval * sizeof(struct asn1_val));
			ret = ENOMEM;
			if (n == NULL)
				goto err;
			if (msg->val) {
				memcpy(n, msg->val,
				    msg->nval * sizeof(struct asn1_val));
				free(msg->val);
			}
			msg->val = n;
		}
		ret = asn1_decode_one(buf, msg->val + msg->nval);
		if (ret != 0)
			goto err;
		msg->nval++;
	}

	msg->buf = asn1_buf_steal(buf);

	return 0;

err:
	asn1_buf_rollback(buf, cp);
	printf("BAD MSG:");
	for (len=0; len<asn1_buf_len(buf); ++len) {
		printf("%02x", buf->buf[buf->off+len]);
	}
	printf("\n");
	if (msg->val)
		free(msg->val);
	memset(msg, 0, sizeof(*msg));

	return ret;
}


const char *
unsol_name(enum xmm_7360_unsol_ids id)
{
#define make_case(id) case id: return #id;
	switch (id) {
	make_case(UtaMsSimApduCmdRspCb)
	make_case(UtaMsSimApplicationRspCb)
	make_case(UtaMsSimInfoIndCb)
	make_case(UtaMsSimInitIndCb)
	make_case(UtaMsSimFullAccessIndCb)
	make_case(UtaMsSimErrorIndCb)
	make_case(UtaMsSimCardIndCb)
	make_case(UtaMsSimApplicationIndCb)
	make_case(UtaMsSimPbReadEntryRspCb)
	make_case(UtaMsSimGenPinRspCb)
	make_case(UtaMsSimModifyLockRspCb)
	make_case(UtaMsSimLockStatusIndCb)
	make_case(UtaMsSimTkMoSmsControlInfoIndCb)
	make_case(UtaMsSimTkProactiveCommandIndCb)
	make_case(UtaMsSimTkEnvelopeResIndCb)
	make_case(UtaMsSimTkTerminalProfileReadRspCb)
	make_case(UtaSimTkProactiveCommandHandlerFunc)
	make_case(UtaMsCpsSetModeRsp)
	make_case(UtaMsCpsSetModeIndCb)
	make_case(UtaMsSsNetworkErrorIndCb)
	make_case(UtaMsSsNetworkRejectIndCb)
	make_case(UtaMsSsNetworkGsmCauseIndCb)
	make_case(UtaMsSsUssdRspCb)
	make_case(UtaMsSsUssdIndCb)
	make_case(UtaMsSsEndIndCb)
	make_case(UtaMsSmsIncomingIndCb)
	make_case(UtaMsSmsSendRspCb)
	make_case(UtaMsSmsSetMemoryAvailableRspCb)
	make_case(UtaMsSmsSimMsgCacheFinishedIndCb)
	make_case(UtaMsSmsSimMsgCountRspCb)
	make_case(UtaMsCallPsDefinePrimaryRspCb)
	make_case(UtaMsCallPsUndefinePrimaryRspCb)
	make_case(UtaMsCallPsGetPrimaryRspCb)
	make_case(UtaMsCallPsSetAuthenticationRspCb)
	make_case(UtaMsCallPsSetDnsRspCb)
	make_case(UtaMsCallPsGetNegotiatedDnsRspCb)
	make_case(UtaMsCallPsGetNegIpAddrRspCb)
	make_case(UtaMsCallPsActivateRspCb)
	make_case(UtaMsCallPsActivateStatusIndCb)
	make_case(UtaMsCallPsDeactivateRspCb)
	make_case(UtaMsCallPsDeactivateIndCb)
	make_case(UtaMsCallPsConnectRspCb)
	make_case(UtaMsNetSingleShotRadioSignalReportingRspCb)
	make_case(UtaMsNetCellInfoIndCb)
	make_case(UtaMsNetConnectionInfoIndCb)
	make_case(UtaMsNetHspaInfoIndCb)
	make_case(UtaMsNetRadioSignalIndCb)
	make_case(UtaMsNetCellChangeIndCb)
	make_case(UtaMsNetAttachRspCb)
	make_case(UtaMsNetPsAttachRspCb)
	make_case(UtaMsNetPsDetachRspCb)
	make_case(UtaMsNetScanRspCb)
	make_case(UtaMsNetPowerDownRspCb)
	make_case(UtaMsNetExtScanRspCb)
	make_case(UtaMsNetPsAttachIndCb)
	make_case(UtaMsNetPsDetachIndCb)
	make_case(UtaMsNetRegistrationInfoIndCb)
	make_case(UtaMsNetIsAttachAllowedIndCb)
	make_case(UtaMsNetGprsClassIndCb)
	make_case(UtaMsNetSetFdConfigRspCb)
	make_case(UtaMsNetFdConfigIndCb)
	make_case(UtaMsNetGetFdConfigRspCb)
	make_case(UtaMsNetConfigureNetworkModeRspCb)
	make_case(UtaMsNetNetworkModeChangeIndCb)
	make_case(UtaMsNetRatModeStatusRspCb)
	make_case(UtaMsNetRatModeStatusIndCb)
	make_case(UtaMsNetDcSetVoiceDomainPreferenceConfigRspCb)
	make_case(UtaMsCallCsSetupCallRspCb)
	make_case(UtaMsCallCsDialingIndCb)
	make_case(UtaMsCallCsAlertingIndCb)
	make_case(UtaMsCallCsCtmInfoIndCb)
	make_case(UtaMsCallCsConnectedIndCb)
	make_case(UtaMsCallCsReleaseCallRspCb)
	make_case(UtaMsCallCsDisconnectingIndCb)
	make_case(UtaMsCallCsDisconnectedIndCb)
	make_case(UtaMsCallCsIncomingCallIndCb)
	make_case(UtaMsCallCsAcceptCallRspCb)
	make_case(UtaMsCallCsProgressIndCb)
	make_case(UtaMsCallCsSwapCallsRspCb)
	make_case(UtaMsCallCsHoldCallRspCb)
	make_case(UtaMsCallCsRetrieveCallRspCb)
	make_case(UtaMsCallCsSplitMptyRspCb)
	make_case(UtaMsCallCsJoinCallsRspCb)
	make_case(UtaMsCallCsTransferCallsRspCb)
	make_case(UtaMsCallCsStartDtmfRspCb)
	make_case(UtaMsCallCsStopDtmfRspCb)
	make_case(UtaMsCallCsStopDtmfExtRspCb)
	make_case(UtaMsCallCsNotificationIndCb)
	make_case(UtaMsCallCsCugInfoIndCb)
	make_case(UtaMsCallCsCallingNameInfoIndCb)
	make_case(UtaMsCallCsEmergencyNumberListIndCb)
	make_case(UtaMsCallCsCallStatusIndCb)
	make_case(UtaCallMultimediaGetMediaProfilesInfoRspCb)
	make_case(UtaMsCallMultimediaSetupCallRspCb)
	make_case(UtaMsCallMultimediaUpdateCallRspCb)
	make_case(UtaMsCallCsVoimsSrvccHoStatusIndCb)
	make_case(UtaMsCpsSetSimModeRsp)
	make_case(UtaMsCpsStartupIndCb)
	make_case(UtaMsSsCallForwardRspCb)
	make_case(UtaMsSsCallWaitingRspCb)
	make_case(UtaMsSsCallBarringRspCb)
	make_case(UtaMsSsIdentificationRspCb)
	make_case(UtaMsSmsDataDownloadRspCb)
	make_case(UtaMsCallPsGetNegQosRspCb)
	make_case(UtaMsCallPsGetTftRspCb)
	make_case(UtaMsCallPsSetPcoRspCb)
	make_case(UtaMsCallPsGetNwPcoRspCb)
	make_case(UtaMsCallPsNwActivateIndCb)
	make_case(UtaMsCallPsNwActivateAcceptRspCb)
	make_case(UtaMsCallPsModifyIndCb)
	make_case(UtaMsCallPsSuspendIndCb)
	make_case(UtaMsCallPsResumeIndCb)
	make_case(UtaMsCallPsSetDataPrefRspCb)
	make_case(UtaMsCbsStartRspCb)
	make_case(UtaMsCbsStopRspCb)
	make_case(UtaMsCbsNewMessageIndCb)
	make_case(UtaMsCbsEtwsConfigRspCb)
	make_case(UtaMsCbsEtwsStartRspCb)
	make_case(UtaMsCbsEtwsStopRspCb)
	make_case(UtaMsCbsEtwsNotifyPrimaryWarningInd)
	make_case(UtaMsCbsEtwsNotifySecondaryWarningInd)
	make_case(UtaMsNetConfigureRxDiversityDarpIndCb)
	make_case(UtaMsNetTimeInfoReadRspCb)
	make_case(UtaMsNetTimeInfoIndCb)
	make_case(UtaMsNetBandStatusRspCb)
	make_case(UtaMsNetBandStatusIndCb)
	make_case(UtaMsNetSetCsgConfigRspCb)
	make_case(UtaMsNetGetCsgConfigRspCb)
	make_case(UtaMsNetGetExtendedRadioSignalInfoRspCb)
	make_case(UtaMsNetNitzInfoIndCb)
	make_case(UtaMsNetDetachRspCb)
	make_case(UtaMsNetSelectGprsClassRspCb)
	make_case(UtaMsNetNetworkFeatureSupportInfoIndCb)
	make_case(UtaMsNetEpsNetworkFeatureSupportInfoIndCb)
	make_case(UtaMsNetCsServiceNotificationIndCb)
	make_case(UtaMsNetDualSimServiceIndCb)
	make_case(UtaMsNetSingleShotFdRspCb)
	make_case(UtaMsSimPbGetLocationRspCb)
	make_case(UtaMsSimPbReadGasEntryRspCb)
	make_case(UtaMsSimPbWriteEntryRspCb)
	make_case(UtaMsSimPbGetMetaInformationRspCb)
	make_case(UtaMsSimPbUsimPbSelectRspCb)
	make_case(UtaMsSimPbGetFreeRecordsRspCb)
	make_case(UtaMsSimPbUsimPbReadyIndCb)
	make_case(UtaMsSimPbCacheLoadFinishedIndCb)
	make_case(UtaMsSimPbCacheLoadIndCb)
	make_case(UtaMsSimGenPinIndCb)
	make_case(UtaMsSimFdnStateIndCb)
	make_case(UtaIdcApMsgSetRspCb)
	make_case(UtaIdcApMsgGetRspCb)
	make_case(UtaIdcCwsMsgSetRspCb)
	make_case(UtaIdcCwsMsgGetRspCb)
	make_case(UtaIdcCwsMsgIndCb)
	make_case(UtaBootPrepareShutdownRspCb)
	make_case(UtaFreqInfoActivateRspCb)
	make_case(UtaFreqInfoDeactivateRspCb)
	make_case(UtaFreqInfoGetFreqInfoRspCb)
	make_case(UtaFreqInfoIndicationCb)
	make_case(UtaModeSetRspCb)
	make_case(UtaModeStartupIndCb)
	make_case(UtaProdGtiCmdRspCb)
	make_case(UtaCellTimeStampRspCb)
	make_case(UtaMsSsLcsMoLocationRspCb)
	make_case(UtaMsSsLcsCapabilitiesIndCb)
	make_case(UtaMsCpAssistanceDataInjectRspCb)
	make_case(UtaMsCpAssistanceDataNeededIndCb)
	make_case(UtaMsCpPosMeasurementRspCb)
	make_case(UtaMsCpPosMeasurementAbortRspCb)
	make_case(UtaMsCpPosReportMeasurementIndCb)
	make_case(UtaMsSimTkExecSmsPpIndCb)
	make_case(UtaMsSimTkExecSimInitiatedCallIndCb)
	make_case(UtaMsSimTkExecSsUssdIndCb)
	make_case(UtaMsSimTkExecDtmfIndCb)
	make_case(UtaMsSimTkExecDtmfEndIndCb)
	make_case(UtaMsSimTkRefreshConfirmIndCb)
	make_case(UtaMsSimTkRefreshFcnIndCb)
	make_case(UtaMsSimTkControlRspCb)
	make_case(UtaMsSimTkTerminalProfileDownloadRspCb)
	make_case(UtaMs3gpp2SmsSendRspCb)
	make_case(UtaMs3gpp2SmsIncomingIndCb)
	make_case(UtaMetricsHandlerFunction)
	make_case(UtaMsEmbmsSetServiceRspCb)
	make_case(UtaMsEmbmsMbsfnAreaConfigRspCb)
	make_case(UtaMsEmbmsSessionConfigRspCb)
	make_case(UtaMsEmbmsSetInterestedTMGIListRspCb)
	make_case(UtaMsEmbmsSetInterestedSAIFreqRspCb)
	make_case(UtaMsEmbmsServiceIndCb)
	make_case(UtaMsEmbmsMBSFNAreaIndCb)
	make_case(UtaMsEmbmsServicesListIndCb)
	make_case(UtaMsEmbmsSAIListIndCb)
	make_case(UtaMsEmbmsMpsInfoIndCb)
	make_case(UtaImsStateChangedIndCb)
	make_case(UtaImsServiceStateChangedIndCb)
	make_case(UtaMsSimOpenChannelRspCb)
	make_case(UtaMsSimCloseChannelRspCb)
	make_case(UtaMsSimBdnStateIndCb)
	make_case(UtaMsSetSimStackMappingRspCb)
	make_case(UtaMsGetSimStackMappingRspCb)
	make_case(UtaMsSimMccMncIndCb)
	make_case(UtaMsSimTkTerminalResponseIndCb)
	make_case(UtaMsNetRegisteredPlmnNameIndCb)
	make_case(UtaMsSimTkSetTerminalCapabilityRspCb)
	make_case(UtaMsSimTkReadTerminalCapabilityRspCb)
	make_case(CsiFccLockQueryRspCb)
	make_case(CsiFccLockGenChallengeRspCb)
	make_case(CsiFccLockVerChallengeRspCb)
	make_case(UtaSensorOpenRspCb)
	make_case(UtaSensorMeasIndCb)
	make_case(CsiSioIpFilterCntrlSetRspCb)
	make_case(CsiSioIpFilterNewCntrlSetRspCb)
	make_case(UtaMsAccCurrentFreqInfoRspCb)
	make_case(UtaMsAccCurrentFreqInfoIndCb)
	make_case(CsiTrcAtCmndRspCb)
	make_case(UtaMsSimApduCmdExtRspCb)
	make_case(UtaMsNetGetPlmnNameInfoRspCb)
	make_case(UtaMsNetSib8TimeInfoIndCb)
	make_case(UtaMsNetGetCountryListRspCb)
	make_case(UtaMsNetExtConfigureNetworkModeRspCb)
	make_case(UtaMsNetExtNetworkModeChangeIndCb)
	make_case(UtaMsNetExtBandStatusRspCb)
	make_case(UtaMsNetExtBandStatusIndCb)
	make_case(UtaMsCallPsAttachApnConfigRspCb)
	make_case(UtaMsCallPsReadContextStatusRspCb)
	make_case(CsiMsSimAccessGetSimStateInfoRspCb)
	make_case(CsiMsNetGetRegistrationInfoRspCb)
	make_case(CsiMsNetLdrGetApnPlmnParameterListRspCb)
	make_case(UtaMsNetLdrApnParametersChangeIndCb)
	default: return "unknown";
	}
}

const char * call_id_name(enum xmm_7360_call_ids id)
{
	switch (id) {
	make_case(UtaMsSimOpenReq)
	make_case(UtaMsSimApduCmdReq)
	make_case(UtaMsSimApplicationReq)
	make_case(UtaMsSimDecodeFcp)
	make_case(UtaMsSimPbReadEntryReq)
	make_case(UtaMsSimGenPinReq)
	make_case(UtaMsSimModifyLockReq)
	make_case(UtaMsSimTkProactiveCommandRsp)
	make_case(UtaMsSimTkEnvelopeCommandReq)
	make_case(UtaMsSimTkTerminalProfileReadReq)
	make_case(UtaMsSimTkRegisterHandler)
	make_case(UtaMsSimTkDeregisterHandler)
	make_case(UtaMsCpsSetModeReq)
	make_case(UtaMsCpsSetStackModeConfiguration)
	make_case(UtaMsCpsSetSimModeConfiguration)
	make_case(UtaMsCpsReadImei)
	make_case(UtaMsCallCsInit)
	make_case(UtaMsCbsInit)
	make_case(UtaMsSsInit)
	make_case(UtaMsSsSendUssdReq)
	make_case(UtaMsSsRespondUssd)
	make_case(UtaMsSsAbort)
	make_case(UtaMsSmsInit)
	make_case(UtaMsSmsSendReq)
	make_case(UtaMsSmsSetMemoryAvailableReq)
	make_case(UtaMsSmsIncomingSmsAck)
	make_case(UtaMsSmsSimMsgCountReq)
	make_case(UtaMsCallPsInitialize)
	make_case(UtaMsCallPsObtainPdpContextId)
	make_case(UtaMsCallPsReleasePdpContextId)
	make_case(UtaMsCallPsDefinePrimaryReq)
	make_case(UtaMsCallPsUndefinePrimaryReq)
	make_case(UtaMsCallPsGetPrimaryReq)
	make_case(UtaMsCallPsSetAuthenticationReq)
	make_case(UtaMsCallPsSetDnsReq)
	make_case(UtaMsCallPsGetNegotiatedDnsReq)
	make_case(UtaMsCallPsGetNegIpAddrReq)
	make_case(UtaMsCallPsActivateReq)
	make_case(UtaMsCallPsDeactivateReq)
	make_case(UtaMsCallPsConnectReq)
	make_case(UtaMsNetOpen)
	make_case(UtaMsNetSetRadioSignalReporting)
	make_case(UtaMsNetSingleShotRadioSignalReportingReq)
	make_case(UtaMsNetAttachReq)
	make_case(UtaMsNetPsAttachReq)
	make_case(UtaMsNetPsDetachReq)
	make_case(UtaMsNetScanReq)
	make_case(UtaMsNetScanAbort)
	make_case(UtaMsNetPowerDownReq)
	make_case(UtaMsNetExtScanReq)
	make_case(UtaMsNetSetFdConfigReq)
	make_case(UtaMsNetGetFdConfigReq)
	make_case(UtaMsNetConfigureNetworkModeReq)
	make_case(UtaMsNetRatModeStatusReq)
	make_case(UtaNvmRead)
	make_case(UtaNvmWrite)
	make_case(UtaNvmWriteCommit)
	make_case(UtaSysGetInfo)
	make_case(UtaRPCPSConnectSetupReq)
	make_case(UtaRPCPsConnectToDatachannelReq)
	make_case(UtaRPCPSConnectReleaseReq)
	make_case(UtaMsNetDcSetVoiceDomainPreferenceConfigReq)
	make_case(UtaMsCallCsSetupVoiceCallReq)
	make_case(UtaMsCallCsReleaseCallReq)
	make_case(UtaMsCallCsAcceptCallReq)
	make_case(UtaMsCallCsSwapCallsReq)
	make_case(UtaMsCallCsHoldCallReq)
	make_case(UtaMsCallCsRetrieveCallReq)
	make_case(UtaMsCallCsSplitMptyReq)
	make_case(UtaMsCallCsJoinCallsReq)
	make_case(UtaMsCallCsTransferCallsReq)
	make_case(UtaMsCallCsStartDtmfReq)
	make_case(UtaMsCallCsStopDtmfReq)
	make_case(UtaMsCallCsSetUus1Info)
	make_case(UtaMsCallCsSetTtyDeviceMode)
	make_case(UtaMsCallCsGetTtyDeviceMode)
	make_case(UtaMsCallMultimediaSetupCallReq)
	make_case(UtaMsCallMultimediaUpdateCallReq)
	make_case(UtaMsCpsSetSimModeReq)
	make_case(UtaMsSsCallForwardReq)
	make_case(UtaMsSsCallWaitingReq)
	make_case(UtaMsSsCallBarringReq)
	make_case(UtaMsSsIdentificationReq)
	make_case(UtaMsSmsSetSendMoreMessagesStatus)
	make_case(UtaMsSmsDataDownloadReq)
	make_case(UtaMsSmsDataDownloadAck)
	make_case(UtaMsCallPsGetNegQosReq)
	make_case(UtaMsCallPsGetTftReq)
	make_case(UtaMsCallPsSetPcoReq)
	make_case(UtaMsCallPsGetNwPcoReq)
	make_case(UtaMsCallPsNwActivateAcceptReq)
	make_case(UtaMsCallPsNwActivateRejectReq)
	make_case(UtaMsCallPsSetDataPrefReq)
	make_case(UtaMsCbsStartReq)
	make_case(UtaMsCbsStopReq)
	make_case(UtaMsCbsSetMsgFilter)
	make_case(UtaMsCbsGetMsgFilter)
	make_case(UtaMsCbsEtwsConfigReq)
	make_case(UtaMsCbsEtwsStartReq)
	make_case(UtaMsCbsEtwsStopReq)
	make_case(UtaMsCpsNvmWrite)
	make_case(UtaMsCpsNvmRead)
	make_case(UtaMsNetConfigureRxDiversityDarp)
	make_case(UtaMsNetLdrGetApnParameterList)
	make_case(UtaMsNetTimeInfoReadReq)
	make_case(UtaMsNetSetCsgConfigReq)
	make_case(UtaMsNetBandStatusReq)
	make_case(UtaMsNetGetExtendedRadioSignalInfoReq)
	make_case(UtaMsNetDetachReq)
	make_case(UtaMsNetSelectGprsClassReq)
	make_case(UtaMsNetGetCsgConfigReq)
	make_case(UtaMsNetCsServiceNotificationAccept)
	make_case(UtaMsNetSingleShotFdReq)
	make_case(UtaMsSimPbLocationReq)
	make_case(UtaMsSimPbReadGasEntryReq)
	make_case(UtaMsSimPbWriteEntryReq)
	make_case(UtaMsSimPbGetMetaInformationReq)
	make_case(UtaMsSimPbUsimPbSelectReq)
	make_case(UtaMsSimPbGetFreeRecordsReq)
	make_case(UtaMsSimCreateReadBinaryApdu)
	make_case(UtaMsSimCreateUpdateBinaryApdu)
	make_case(UtaMsSimAnalyseReadResult)
	make_case(UtaMsSimSetFdnReq)
	make_case(SetApScreenState)
	make_case(UtaIoCtl)
	make_case(UtaIdcApMsgSetReq)
	make_case(UtaIdcApMsgGetReq)
	make_case(UtaIdcEnbleReq)
	make_case(UtaIdcCwsMsgSetReq)
	make_case(UtaIdcCwsMsgGetReq)
	make_case(UtaIdcSubscribeIndications)
	make_case(UtaIdcUnsubscribeIndications)
	make_case(UtaBootPrepareShutdownReq)
	make_case(UtaBootShutdownReq)
	make_case(UtaRfMaxTxPwrSet2g)
	make_case(UtaRfMaxTxPwrSet3g)
	make_case(UtaRfMaxTxPwrSet4g)
	make_case(UtaFreqInfoActivateReq)
	make_case(UtaFreqInfoGetFreqInfoReq)
	make_case(UtaFreqInfoDeactivateReq)
	make_case(UtaFreqInfoRegisterIndications)
	make_case(UtaFreqInfoDeregisterIndications)
	make_case(UtaModeSetReq)
	make_case(UtaNvmFlushSync)
	make_case(UtaProdRegisterGtiCallbackFunc)
	make_case(UtaProdGtiCmdReq)
	make_case(UtaCellTimeStampReq)
	make_case(UtaMsSsLcsInit)
	make_case(UtaMsSsLcsMoLocationReq)
	make_case(UtaMsSsLcsMtlrNotificationRsp)
	make_case(UtaMsCpAssistanceDataInjectReq)
	make_case(UtaMsCpResetAssistanceData)
	make_case(UtaMsCpPosMeasurementReq)
	make_case(UtaMsCpPosMeasurementAbortReq)
	make_case(UtaMsCpPosEnableMeasurementReport)
	make_case(UtaMsCpPosDisableMeasurementReport)
	make_case(UtaMsSimTkInit)
	make_case(UtaMsSimTkExecSmsPpRsp)
	make_case(UtaMsSimTkExecSimInitiatedCallRsp)
	make_case(UtaMsSimTkExecSsUssdRsp)
	make_case(UtaMsSimTkExecDtmfRsp)
	make_case(UtaMsSimTkStopDtmfReq)
	make_case(UtaMsSimTkRefreshConfirmRsp)
	make_case(UtaMsSimTkRefreshFcnRsp)
	make_case(UtaMsSimTkControlReq)
	make_case(UtaMsSimTkTerminalProfileDownloadReq)
	make_case(UtaMs3gpp2SmsSendReq)
	make_case(UtaMs3gpp2SmsSubscribeIndications)
	make_case(UtaMs3gpp2SmsUnsubscribeIndications)
	make_case(RpcGetRemoteVerInfo)
	make_case(UtaMsMetricsRegisterHandler)
	make_case(UtaMsMetricsDeregisterHandler)
	make_case(UtaMsMetricsSetOptions)
	make_case(UtaMsMetricsTrigger)
	make_case(UtaMsEmbmsInit)
	make_case(UtaMsEmbmsSetServiceReq)
	make_case(UtaMsEmbmsMbsfnAreaConfigReq)
	make_case(UtaMsEmbmsSessionConfigReq)
	make_case(UtaMsEmbmsSetInterestedTMGIListReq)
	make_case(UtaMsEmbmsSetInterestedSAIFreqReq)
	make_case(UtaImsSubscribeIndications)
	make_case(UtaImsUnsubscribeIndications)
	make_case(UtaImsGetFrameworkState)
	make_case(UtaRtcGetDatetime)
	make_case(UtaMsSimAnalyseSimApduResult)
	make_case(UtaMsSimOpenChannelReq)
	make_case(UtaMsSimCloseChannelReq)
	make_case(UtaMsSimSetBdnReq)
	make_case(UtaMsSetSimStackMappingReq)
	make_case(UtaMsGetSimStackMappingReq)
	make_case(UtaMsNetSetRadioSignalReportingConfiguration)
	make_case(UtaPCIeEnumerationextTout)
	make_case(UtaMsSimTkSetTerminalCapabilityReq)
	make_case(UtaMsSimTkReadTerminalCapabilityReq)
	make_case(CsiFccLockQueryReq)
	make_case(CsiFccLockGenChallengeReq)
	make_case(CsiFccLockVerChallengeReq)
	make_case(UtaSensorOpenReq)
	make_case(UtaSensorCloseExt)
	make_case(UtaSensorStartExt)
	make_case(UtaSensorSetAlarmParamExt)
	make_case(UtaSensorSetSchedulerParamExt)
	make_case(CsiSioIpFilterCntrlSetReq)
	make_case(UtaMsAccCurrentFreqInfoReq)
	make_case(CsiTrcAtCmndReq)
	make_case(UtaMsSimApduCmdExtReq)
	make_case(UtaMsNetGetPlmnNameInfoReq)
	make_case(UtaMsNetGetCountryListReq)
	make_case(UtaMsNetExtConfigureNetworkModeReq)
	make_case(UtaMsNetExtBandStatusReq)
	make_case(UtaMsCallPsAttachApnConfigReq)
	make_case(CsiMsCallPsInitialize)
	make_case(UtaAudioEnableSource)
	make_case(UtaAudioDisableSource)
	make_case(UtaAudioConfigureDestinationExt)
	make_case(UtaAudioSetDestinationsForSource)
	make_case(UtaAudioSetVolumeForSource)
	make_case(UtaAudioSetMuteForSourceExt)
	make_case(UtaAudioSetVolumeForDestination)
	make_case(UtaAudioSetMuteForDestinationExt)
	make_case(UtaAudioConfigureSourceExt)
	make_case(UtaAudioSetDestinationsForSourceExt)
	make_case(UtaRPCScreenControlReq)
	make_case(UtaMsCallPsReadContextStatusReq)
	make_case(CsiMsSimAccessGetSimStateInfoReq)
	make_case(CsiMsNetGetRegistrationInfoReq)
	make_case(CsiSioIpFilterNewCntrlSetReq)
	make_case(CsiMsNetLdrGetApnPlmnParameterListReq)
	make_case(RPCGetAPIParamChangedBitmap)
	}
#undef make_case
}

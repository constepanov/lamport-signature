package org.suai.crypto.util;

import org.knowm.xchart.SwingWrapper;
import org.knowm.xchart.XYChart;
import org.knowm.xchart.XYChartBuilder;
import org.knowm.xchart.style.Styler;
import org.suai.crypto.lamport.LamportSignature;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public class SignatureAnalyzer {
    public static void plotPrivateKeySizeDependenceOnMessageSize() {
        XYChart chart = new XYChartBuilder()
                .width(800).height(600)
                .theme(Styler.ChartTheme.Matlab)
                .title("Private or public key size dependence on message Size")
                .xAxisTitle("Message size (bits)").yAxisTitle("Private key size (bits)")
                .build();

        chart.getStyler().setLegendVisible(false);
        chart.getStyler().setLegendPosition(Styler.LegendPosition.InsideNE);

        List<Integer> publicKeySizes = new ArrayList<>();
        List<Integer> messageSizes = new ArrayList<>();
        for (int i = 1; i < 6; i++) {
            int messageSize = i * 8;
            int publicKeySize = 2 * messageSize * 256;
            messageSizes.add(messageSize);
            publicKeySizes.add(publicKeySize);
        }

        chart.addSeries("abc", messageSizes, publicKeySizes);

        new SwingWrapper(chart).displayChart();
    }

    public static void plotSignatureSizeDependenceOnMessageSize() {
        XYChart chart = new XYChartBuilder()
                .width(800).height(600)
                .theme(Styler.ChartTheme.Matlab)
                .title("Signature size dependence on message Size")
                .xAxisTitle("Message size (bits)").yAxisTitle("Signature size (bits)")
                .build();

        chart.getStyler().setLegendVisible(false);
        chart.getStyler().setLegendPosition(Styler.LegendPosition.InsideNE);

        List<Integer> signatureSizes = new ArrayList<>();
        List<Integer> messageSizes = new ArrayList<>();
        for (int i = 1; i < 6; i++) {
            int messageSize = i * 8;
            int signatureSize = messageSize * 256;
            messageSizes.add(messageSize);
            signatureSizes.add(signatureSize);
        }

        chart.addSeries("abc", messageSizes, signatureSizes);

        new SwingWrapper(chart).displayChart();
    }

    public static void plotSignatureSignAndVerifyTimeDependenceOnMessageSize() throws NoSuchAlgorithmException {
        XYChart chart = new XYChartBuilder()
                .width(800).height(600)
                .theme(Styler.ChartTheme.Matlab)
                .title("Signature sign and verify time dependence on message size")
                .xAxisTitle("Message size (bits)").yAxisTitle("Time")
                .build();

        chart.getStyler().setLegendPosition(Styler.LegendPosition.InsideNE);

        List<Long> signTimeList = new ArrayList<>();
        List<Long> verifyTimeList = new ArrayList<>();
        List<Integer> messageSizes = new ArrayList<>();
        SecureRandom random = new SecureRandom();
        for (int i = 1000; i < 33000; i += 3000) {
            int messageSize = i * 8;
            byte[] message = new byte[i];
            random.nextBytes(message);
            LamportSignature lamport = new LamportSignature(messageSize);
            KeyPair keyPair = lamport.generateKeyPair();

            long signStartTime = System.currentTimeMillis();
            BigInteger[] signature = lamport.sign(message, keyPair.getPrivate());
            long signTime = System.currentTimeMillis() - signStartTime;

            long verifyStartTime = System.currentTimeMillis();
            lamport.verify(message, signature, keyPair.getPublic());
            long verifyTime = System.currentTimeMillis() - verifyStartTime;
            messageSizes.add(messageSize);
            signTimeList.add(signTime);
            verifyTimeList.add(verifyTime);
        }

        chart.addSeries("sign", messageSizes, signTimeList);
        chart.addSeries("verify", messageSizes, verifyTimeList);


        new SwingWrapper(chart).displayChart();
    }
}

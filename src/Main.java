import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.FixedPointUtil;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.Date;

public class Main {
    private static final X9ECParameters CURVE_PARAMS;
    private static final ECDomainParameters CURVE;
    private static final BigInteger HALF_CURVE_ORDER;
    private static final ECNamedCurveParameterSpec ecSpec;
    private static final SecureRandom secureRandom;

    static {
        CURVE_PARAMS = CustomNamedCurves.getByName("P-384");
        ecSpec = ECNamedCurveTable.getParameterSpec("P-384");

        FixedPointUtil.precompute(CURVE_PARAMS.getG(), 12);

        CURVE = new ECDomainParameters(
                CURVE_PARAMS.getCurve(),
                CURVE_PARAMS.getG(),
                CURVE_PARAMS.getN(),
                CURVE_PARAMS.getH(),
                CURVE_PARAMS.getSeed());

        HALF_CURVE_ORDER = CURVE_PARAMS.getN().shiftRight(1);

        try {
            secureRandom = new SecureRandom();
            secureRandom.setSeed(new Date().getTime());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        generateAndSavePem("name");
    }

    private static void generateAndSavePem(String name) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "BC");
        g.initialize(ecSpec, secureRandom);

        KeyPair keyPair = g.generateKeyPair();

        String pk = exportPrivate(keyPair);
        System.out.println(pk);
        Files.write(Paths.get(name + ".pem"), Arrays.asList(pk));
    }

    public static String exportPrivate(KeyPair keyPair) throws Exception {
        StringWriter sw = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(sw);
        pemWriter.writeObject(keyPair.getPrivate());
        pemWriter.close();
        return sw.toString();
    }
}

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jcajce.provider.keystore.PKCS12;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.FixedPointUtil;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
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

    public static void main(String[] args) throws GeneralSecurityException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "BC");
        g.initialize(ecSpec, secureRandom);

        KeyPair keyPair = g.generateKeyPair();

        String encodeToString = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
        System.out.println(encodeToString);
    }
}

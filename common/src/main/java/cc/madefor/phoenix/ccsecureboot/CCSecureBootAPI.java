package cc.madefor.phoenix.ccsecureboot;

import cc.madefor.phoenix.ccsecureboot.mixin.ServerContextAccessor;
import dan200.computercraft.api.ComputerCraftAPI;
import dan200.computercraft.api.lua.*;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import org.jspecify.annotations.Nullable;

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Date;

public class CCSecureBootAPI implements ILuaAPI {
    private final IComputerSystem computer;
    private @Nullable Certificate rootCertificate = null;
    private @Nullable PrivateKey rootKey = null;
    private @Nullable String mountPath = null;

    public CCSecureBootAPI(IComputerSystem computer) {
        this.computer = computer;
    }

    @LuaFunction
    public final ByteBuffer enroll(ByteBuffer pem) throws LuaException {
        if (rootKey == null) {
            throw new LuaException("An error occurred while loading the root key; check the server logs for more information.");
        }
        // TODO: should probably check if the computer is already enrolled?
        try {
            var bytes = new byte[pem.remaining()];
            pem.get(bytes);
            var reader = new PemReader(new InputStreamReader(new ByteArrayInputStream(bytes)));
            var data = reader.readPemObject();
            reader.close();

            var csr = new PKCS10CertificationRequest(data.getContent());
            var rdns = csr.getSubject().getRDNs(new ASN1ObjectIdentifier("2.5.4.45"));
            if (rdns.length == 0) {
                throw new LuaException("CSR does not contain computer ID");
            }

            var id_bytes = ((ASN1OctetString)rdns[0].getFirst().getValue()).getOctets();
            var id_str = new String(id_bytes, StandardCharsets.ISO_8859_1);
            if (!id_str.equals(String.valueOf(computer.getID()))) {
                throw new LuaException("CSR ID does not match computer ID");
            }

            var cert = sign(csr, rootKey);
            var stream = new ByteArrayOutputStream();
            var writer = new PemWriter(new OutputStreamWriter(stream));
            writer.writeObject(new PemObject("CERTIFICATE", cert.getEncoded()));
            writer.close();

            var file = computer.getLevel().getServer().getWorldPath(ServerContextAccessor.getFolder()).resolve("certs/enrolled/" + computer.getID()).toFile();
            file.getParentFile().mkdirs();
            file.createNewFile();
            return ByteBuffer.wrap(stream.toByteArray());
        } catch (Exception e) {
            throw new LuaException("Could not sign certificate: " + e.getMessage());
        }
    }

    @LuaFunction
    public final MethodResult unenroll(ByteBuffer certbuf, ByteBuffer sigbuf) {
        if (rootCertificate == null) {
            return MethodResult.of(false, "An error occurred while loading the root certificate; check the server logs for more information.");
        }
        // TODO: should probably check if the computer is already unenrolled?
        try {
            var certbytes = new byte[certbuf.remaining()];
            certbuf.get(certbytes);
            var reader = new PemReader(new InputStreamReader(new ByteArrayInputStream(certbytes)));
            var certdata = reader.readPemObject();
            reader.close();
            var cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(certdata.getContent()));
            // TODO: check CRL
            cert.verify(rootCertificate.getPublicKey());

            var sigbytes = new byte[sigbuf.remaining()];
            sigbuf.get(sigbytes);

            var sig = Signature.getInstance("Ed25519");
            sig.initVerify(cert);
            var rdns = new JcaX509CertificateHolder(cert).getSubject().getRDNs(new ASN1ObjectIdentifier("2.5.4.45"));
            if (rdns.length == 0) {
                return MethodResult.of(false, "Certificate does not contain computer ID");
            }
            var id_bytes = ((ASN1OctetString)rdns[0].getFirst().getValue()).getOctets();
            sig.update(id_bytes);
            if (!sig.verify(sigbytes)) {
                return MethodResult.of(false, "Could not verify signature");
            }

            // TODO: revoke certificate
            var file = computer.getLevel().getServer().getWorldPath(ServerContextAccessor.getFolder()).resolve("certs/enrolled/" + computer.getID()).toFile();
            return MethodResult.of(file.delete());
        } catch (Exception e) {
            return MethodResult.of(false, e.getMessage());
        }
    }

    @Override
    public String[] getNames() {
        return new String[0];
    }

    @Override
    public @Nullable String getModuleName() {
        return "secureboot";
    }

    @Override
    public void startup() {
        ILuaAPI.super.startup();
        var server = computer.getLevel().getServer();
        mountPath = computer.mount("rom/pxboot/certs", ComputerCraftAPI.createSaveDirMount(server, "certs", 0), "certs");
        PublicKey pk = null;
        if (rootKey == null) {
            var file = server.getWorldPath(ServerContextAccessor.getFolder()).resolve("root.key").toFile();
            if (file.exists()) {
                try {
                    PemReader reader = new PemReader(new FileReader(file));
                    var pemObject = reader.readPemObject();
                    reader.close();
                    var pk8 = new PKCS8EncodedKeySpec(pemObject.getContent());
                    var factory = KeyFactory.getInstance("Ed25519");
                    rootKey = factory.generatePrivate(pk8);
                } catch (Exception e) {
                    CCSecureBoot.LOG.warn("Failed to read root.key from file: {}", e.getMessage());
                }
            } else {
                CCSecureBoot.LOG.info("Creating secure boot root key");
                try {
                    var keypair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
                    rootKey = keypair.getPrivate();
                    assert rootKey.getFormat().equals("PKCS#8");
                    pk = keypair.getPublic();
                    file.getParentFile().mkdirs();
                    PemWriter writer = new PemWriter(new FileWriter(file));
                    writer.writeObject(new PemObject("PRIVATE KEY", rootKey.getEncoded()));
                    writer.close();
                } catch (Exception e) {
                    CCSecureBoot.LOG.error("Could not create private key: {}", e.getMessage());
                }
            }
        }
        if (rootKey != null && rootCertificate == null) {
            var file = server.getWorldPath(ServerContextAccessor.getFolder()).resolve("certs/root.pem").toFile();
            if (file.exists()) {
                try {
                    PemReader reader = new PemReader(new FileReader(file));
                    var pemObject = reader.readPemObject();
                    reader.close();
                    rootCertificate = CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(pemObject.getContent()));
                } catch (Exception e) {
                    CCSecureBoot.LOG.warn("Failed to read root.pem from file: {}", e.getMessage());
                }
            } else {
                CCSecureBoot.LOG.info("Creating secure boot root certificate");
                try {
                    if (pk == null) {
                        var generator = KeyPairGenerator.getInstance("Ed25519");
                        var pk8 = PrivateKeyInfo.getInstance(rootKey.getEncoded());
                        generator.initialize(new NamedParameterSpec("Ed25519"), new StaticSecureRandom(pk8.getPrivateKey().getOctets()));
                        pk = generator.generateKeyPair().getPublic();
                    }
                    var csrbuilder = new JcaPKCS10CertificationRequestBuilder(new X500Principal("CN=CCSecureBoot Root"), pk);
                    var csbuilder = new JcaContentSignerBuilder("Ed25519");
                    var signer = csbuilder.build(rootKey);
                    var csr = csrbuilder.build(signer);
                    rootCertificate = sign(csr, rootKey);
                    file.getParentFile().mkdirs();
                    PemWriter writer = new PemWriter(new FileWriter(file));
                    writer.writeObject(new PemObject("CERTIFICATE", rootCertificate.getEncoded()));
                    writer.close();
                } catch (Exception e) {
                    CCSecureBoot.LOG.error("Could not create certificate: {}", e.getMessage());
                }
            }
        }
    }

    @Override
    public void shutdown() {
        ILuaAPI.super.shutdown();
        if (mountPath != null) {
            computer.unmount(mountPath);
        }
    }

    // https://stackoverflow.com/questions/58583774/how-to-generate-publickey-for-privatekey-in-x25519
    private static class StaticSecureRandom extends SecureRandom {
        private final byte[] privateKey;

        public StaticSecureRandom(byte[] privateKey) {
            this.privateKey = privateKey.clone();
        }

        @Override
        public void nextBytes(byte[] bytes) {
            System.arraycopy(privateKey, 2, bytes, 0, privateKey.length - 2);
        }
    }

    // https://www.baeldung.com/java-bouncy-castle-sign-csr
    private X509Certificate sign(PKCS10CertificationRequest inputCSR, PrivateKey caPrivate) throws IOException, OperatorCreationException, CertificateException, NoSuchProviderException {
        var sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("Ed25519");
        var digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);

        var foo = PrivateKeyFactory.createKey(caPrivate.getEncoded());
        SubjectPublicKeyInfo keyInfo = inputCSR.getSubjectPublicKeyInfo();

        var myCertificateGenerator = new X509v3CertificateBuilder(
            new X500Name("CN=CCSecureBoot Root"),
            new BigInteger("1"),
            new Date(System.currentTimeMillis()),
            new Date(System.currentTimeMillis() + 30L * 365 * 24 * 60 * 60 * 1000),
            inputCSR.getSubject(),
            keyInfo);

        var sigGen = new JcaContentSignerBuilder("Ed25519").build(caPrivate);

        var holder = myCertificateGenerator.build(sigGen);
        var eeX509CertificateStructure = holder.toASN1Structure();

        var cf = CertificateFactory.getInstance("X.509");

        var is1 = new ByteArrayInputStream(eeX509CertificateStructure.getEncoded());
        var theCert = (X509Certificate) cf.generateCertificate(is1);
        is1.close();
        return theCert;
    }
}

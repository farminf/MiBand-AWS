//package nodomain.freeyourgadget.gadgetbridge.techedge;
//
///**
// * Created by farmin on 6/15/2016.
// */
//import java.net.URL;
//import java.util.HashMap;
//import java.io.*;
//import java.security.*;
//import java.security.cert.*;
//import javax.net.ssl.*;
//
//import org.spongycastle.jce.provider.X509CertificateObject;
//import org.spongycastle.openssl.*;
//import org.spongycastle.util.io.pem.PemReader;
//
//
//import android.content.Context;
//import android.net.Uri;
//import android.util.Log;
//
//import nodomain.freeyourgadget.gadgetbridge.R;
//
//
//public class SslUtility {
//
//    private static SslUtility		mInstance = null;
//    private Context					mContext = null;
//    private HashMap<Integer, SSLSocketFactory> mSocketFactoryMap = new HashMap<Integer, SSLSocketFactory>();
//
//    public SslUtility(Context context) {
//        mContext = context;
//    }
//
//    public static SslUtility getInstance( ) {
//        if ( null == mInstance ) {
//            throw new RuntimeException("first call must be to SslUtility.newInstance(Context) ");
//        }
//        return mInstance;
//    }
//
//    public static SslUtility newInstance( Context context ) {
//        if ( null == mInstance ) {
//            mInstance = new SslUtility( context );
//        }
//        return mInstance;
//    }
//
////    public SSLSocketFactory getSocketFactory(int certificateId, String certificatePassword ) {
////
////        SSLSocketFactory result = mSocketFactoryMap.get(certificateId);  	// check to see if already created
////
////        if ( ( null == result) && ( null != mContext ) ) {					// not cached so need to load server certificate
////
////            try {
////                KeyStore keystoreTrust = KeyStore.getInstance("BKS");		// Bouncy Castle
////
////                keystoreTrust.load(mContext.getResources().openRawResource(certificateId),
////                        certificatePassword.toCharArray());
////
////                TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
////
////                trustManagerFactory.init(keystoreTrust);
////
////                SSLContext sslContext = SSLContext.getInstance("TLS");
////
////                sslContext.init(null, trustManagerFactory.getTrustManagers(), new SecureRandom());
////
////                result = sslContext.getSocketFactory();
////
////                mSocketFactoryMap.put( certificateId, result);	// cache for reuse
////            }
////            catch ( Exception ex ) {
////                // log exception
////            }
////        }
////
////        return result;
////    }
//
//    static SSLSocketFactory getSocketFactory ( final String password) throws Exception
//    {
//        Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
//        // load CA certificate
//        Uri path = Uri.parse("android.resource://nodomain.freeyourgadget.gadgetbridge/" + R.raw.aws_root );
//
//        String path_string = path.toString();
//        //org.spongycastle.util.io.pem.PemReader reader = new PemReader(new InputStreamReader(new ByteArrayInputStream(File.readAllBytes(R.raw.aws_root))));
//        org.spongycastle.util.io.pem.PemReader reader = new PemReader(new InputStreamReader(ReadinBytes (path_string)));
//       // X509Certificate caCert = (X509Certificate)reader.readPemObject();
//        Object pemObject = reader.readPemObject();
//        X509Certificate caCert = (X509Certificate)pemObject;
//        reader.close();
//        //Log.i("uri" , " : " +  SslUtility.this.getPackageName());
//        // load client certificate
//        Uri path2 = Uri.parse("android.resource://nodomain.freeyourgadget.gadgetbridge/raw/aws_certificate_pem" );
//        String path_string2 = path2.toString();
//       // reader = new PemReader(new InputStreamReader(new ByteArrayInputStream(Files.readAllBytes(Paths.get(crtFile)))));
//        reader =new PemReader(new InputStreamReader(ReadinBytes (path_string2)));
//        Object pemObject2 = reader.readPemObject();
//        X509Certificate cert = (X509Certificate)pemObject2;
//        reader.close();
//
//        // load client private key
//        Uri path3 = Uri.parse("android.resource://nodomain.freeyourgadget.gadgetbridge/raw/aws_private_pem  " );
//        String path_string3 = path3.toString();
//        reader = new PemReader( new InputStreamReader(ReadinBytes (path_string3)));
//        Object pemObject3 = reader.readPemObject();
//        KeyPair key = (KeyPair)pemObject3;
//        reader.close();
//
//        // CA certificate is used to authenticate server
//        KeyStore caKs = KeyStore.getInstance("JKS");
//        caKs.load(null, null);
//        caKs.setCertificateEntry("ca-certificate", caCert);
//        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
//        tmf.init(caKs);
//
//        // client key and certificates are sent to server so it can authenticate us
//        KeyStore ks = KeyStore.getInstance("JKS");
//        ks.load(null, null);
//        ks.setCertificateEntry("certificate", cert);
//        ks.setKeyEntry("private-key", key.getPrivate(), password.toCharArray(), new java.security.cert.Certificate[]{cert});
//        KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX");
//        kmf.init(ks, password.toCharArray());
//
//        // finally, create SSL socket factory
//        SSLContext context = SSLContext.getInstance("TLSv1");
//        context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
//
//        return context.getSocketFactory();
//    }
//
//    private static BufferedInputStream ReadinBytes(String path){
//        BufferedInputStream buf = null;
//        File file = new File(path);
//        if ( file.exists()){
//            Log.i("File" , "file exists!!!!!!");
//        }else{
//            Log.i("File" , "file does  NOT exists!!!!!!");
//
//        }
//        int size = (int) file.length();
//        byte[] bytes = new byte[size];
//        try {
//            buf = new BufferedInputStream(new FileInputStream(file));
//            buf.read(bytes, 0, bytes.length);
//
//            buf.close();
//
//        } catch (FileNotFoundException e) {
//            // TODO Auto-generated catch block
//            e.printStackTrace();
//        } catch (IOException e) {
//            // TODO Auto-generated catch block
//            e.printStackTrace();
//        }
//        return buf;
//    }
//
//}
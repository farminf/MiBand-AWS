//package nodomain.freeyourgadget.gadgetbridge.techedge;
//
///**
// * Created by farmin on 6/15/2016.
// */
//import org.eclipse.paho.client.mqttv3.MqttClient;
//import org.eclipse.paho.client.mqttv3.MqttConnectOptions;
//import org.eclipse.paho.client.mqttv3.MqttDeliveryToken;
//import org.eclipse.paho.client.mqttv3.MqttException;
//import org.eclipse.paho.client.mqttv3.MqttPersistenceException;
//import org.eclipse.paho.client.mqttv3.persist.MemoryPersistence;
//
//public class AccessMqtt {
//
//    private MqttClient 				mMqttClient = null;
//
//    public boolean init( String mqttBrokerURL, String mqttClientId) {
//
//        if ( null == mMqttClient) {
//            try {
//                mMqttClient = new MqttClient(mqttBrokerURL, mqttClientId, new MemoryPersistence());
//
//                if ( null != mMqttClient)  {
//
//                    MqttConnectOptions options = new MqttConnectOptions();
//
////                    options.setUserName(mqttAccountName);
////                    options.setPassword(mqttAccountPassword.toCharArray());
//                    //options.setSocketFactory(SslUtil.getSocketFactory("caFilePath", "clientCrtFilePath", "clientKeyFilePath", "password"));
//
//                    options.setSocketFactory(SslUtility.getInstance().getSocketFactory(""));
//                    options.setCleanSession(true);
//
//                    mMqttClient.connect(options);
//                }
//            }
//            catch ( MqttException ex) {
//                // log exception
//                reset();
//            } catch (Exception e) {
//                e.printStackTrace();
//            }
//        }
//
//        return null != mMqttClient;
//    }
//
//    public boolean write( String mqttTopic, String mqttMessage ) {
//
//        MqttDeliveryToken deliveryToken = null;
//
//        if ( null != mMqttClient ) {
//            try {
//                deliveryToken = mMqttClient.getTopic(mqttTopic).publish(mqttMessage.getBytes(), 1, false);
//            }
//            catch ( MqttPersistenceException ex ) {
//                // log exception
//            }
//            catch ( MqttException  ex ) {
//                // log exception
//            }
//        }
//        return null != deliveryToken;
//    }
//
//    public void reset( ) {
//
//        if ( null != mMqttClient ) {
//
//            try {
//                if ( mMqttClient.isConnected() ) {
//                    mMqttClient.disconnect(0);
//                }
//            }
//            catch ( MqttException ex) {
//                // log exception
//            }
//
//            mMqttClient = null;
//        }
//    }
//
//}

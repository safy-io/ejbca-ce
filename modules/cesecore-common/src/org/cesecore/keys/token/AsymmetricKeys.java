/*
 * Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package org.cesecore.keys.token;

import com.amazonaws.cloudhsm.jce.jni.exception.AddAttributeException;
import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import com.amazonaws.cloudhsm.jce.provider.attributes.*;

import java.math.BigInteger;
import java.security.*;

/** Asymmetric key generation examples. */
public class AsymmetricKeys {
    /**
     * Generate an EC key pair using the given curve. The label passed will be appended with
     * ":Public" and ":Private" for the respective keys. Supported curves are documented here:
     * https://docs.aws.amazon.com/cloudhsm/latest/userguide/java-lib-supported.html Curve params
     * list: EcParams.EC_CURVE_PRIME256; EcParams.EC_CURVE_PRIME384; EcParams.EC_CURVE_SECP256;
     *
     * @return a key pair object that represents the keys on the HSM.
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static KeyPair generateECKeyPair(byte[] curveParams, String label)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException,
                    NoSuchProviderException, AddAttributeException {

        final KeyPairGenerator keyPairGen =
                KeyPairGenerator.getInstance("EC", CloudHsmProvider.PROVIDER_NAME);

        // Set attributes for EC public key
        final KeyAttributesMap publicKeyAttrsMap = new KeyAttributesMap();
        publicKeyAttrsMap.put(KeyAttribute.LABEL, label + ":Public");
        publicKeyAttrsMap.put(KeyAttribute.EC_PARAMS, curveParams);

        // Set attributes for EC private key
        final KeyAttributesMap privateKeyAttrsMap =
                new KeyAttributesMapBuilder().put(KeyAttribute.LABEL, label).build();

        // Create KeyPairAttributesMap and use that to initialize the keyPair generator
        KeyPairAttributesMap keyPairSpec =
                new KeyPairAttributesMapBuilder()
                        .withPublic(publicKeyAttrsMap)
                        .withPrivate(privateKeyAttrsMap)
                        .build();
        keyPairGen.initialize(keyPairSpec);

        return keyPairGen.generateKeyPair();
    }

    /**
     * Generate an RSA key pair.
     *
     * <p>The label passed will be appended with ":Public" and ":Private" for the respective keys.
     *
     * @return a key pair object that represents the keys on the HSM.
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static KeyPair generateRSAKeyPair(int keySizeInBits, String label)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException,
                    NoSuchProviderException, AddAttributeException {
        return generateRSAKeyPair(
                keySizeInBits, label, new KeyAttributesMap(), new KeyAttributesMap());
    }

    /**
     * Generate an RSA key pair and the given provider.
     *
     * <p>The label passed will be appended with ":Public" and ":Private" for the respective keys.
     *
     * @return a key pair object that represents the keys on the HSM.
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static KeyPair generateRSAKeyPair(int keySizeInBits, String label, String providerName)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException,
            NoSuchProviderException, AddAttributeException {
        return doGenerateRSAKeyPair(
                keySizeInBits, label, new KeyAttributesMap(), new KeyAttributesMap(), providerName);
    }

    /**
     * Generate an RSA key pair.
     *
     * <p>The label passed will be appended with ":Public" and ":Private" for the respective keys.
     *
     * @return a key pair object that represents the keys on the HSM.
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static KeyPair generateRSAKeyPair(
            int keySizeInBits,
            String label,
            KeyAttributesMap additionalPublicKeyAttributes,
            KeyAttributesMap additionalPrivateKeyAttributes)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException,
                    NoSuchProviderException, AddAttributeException {
        return doGenerateRSAKeyPair(keySizeInBits,
                label,
                additionalPublicKeyAttributes,
                additionalPrivateKeyAttributes,
                CloudHsmProvider.PROVIDER_NAME);
    }

    private static KeyPair doGenerateRSAKeyPair(int keySizeInBits,
                                                String label,
                                                KeyAttributesMap additionalPublicKeyAttributes,
                                                KeyAttributesMap additionalPrivateKeyAttributes,
                                                String providerName)
                                                throws InvalidAlgorithmParameterException, NoSuchAlgorithmException,
                                                NoSuchProviderException, AddAttributeException {

        KeyPairGenerator keyPairGen =
                KeyPairGenerator.getInstance("RSA", providerName);

        // Set attributes for RSA public key
        final KeyAttributesMap publicKeyAttrsMap = new KeyAttributesMap();
        publicKeyAttrsMap.putAll(additionalPublicKeyAttributes);
        publicKeyAttrsMap.put(KeyAttribute.LABEL, label + ":Public");
        publicKeyAttrsMap.put(KeyAttribute.MODULUS_BITS, keySizeInBits);
        publicKeyAttrsMap.put(KeyAttribute.PUBLIC_EXPONENT, new BigInteger("65537").toByteArray());

        // Set attributes for RSA private key
        final KeyAttributesMap privateKeyAttrsMap = new KeyAttributesMap();
        privateKeyAttrsMap.putAll(additionalPrivateKeyAttributes);
        privateKeyAttrsMap.put(KeyAttribute.LABEL, label);

        // Create KeyPairAttributesMap and use that to initialize the keyPair generator
        KeyPairAttributesMap keyPairSpec =
                new KeyPairAttributesMapBuilder()
                        .withPublic(publicKeyAttrsMap)
                        .withPrivate(privateKeyAttrsMap)
                        .build();

        keyPairGen.initialize(keyPairSpec);

        return keyPairGen.generateKeyPair();
    }
}

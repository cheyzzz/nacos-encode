/*
 * Copyright 1999-2018 Alibaba Group Holding Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.alibaba.nacos.config.server.utils;

import org.apache.commons.lang.StringUtils;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;
/**
 * Has nothing to do with the specific implementation of the consistency protocol Initialization sequence： init(Config).
 *
 * <ul>
 *
 *     for example, the Raft protocol needs to set the election timeout time, the location where
 *     the Log is stored, and the snapshot task execution interval</li>
 *     protocol, such as leader, term, and other metadata information in the Raft protocol</li>
 * </ul>
 *
 * @author <a href="mailto:liaochuntao@live.com">liaochuntao</a>
 */

public class EncryptUtils {

    private static final String DB_ENCRYPT_KEY = "BOCCBMT@2021";

    /**
     *Obtain data according to the request.
     * @param bytes bytes
     * @throws Exception {@link Exception}
     */
    
    public static String base64Encode(byte[] bytes) {
        return new String(Base64.getEncoder().encode(bytes));
    }

    /**
     * Obtain data according to the request.
     *
     * @param base64String base64String
     * @throws Exception {@link Exception}
     */
    
    public static byte[] base64Decode(String base64String) {
        return Base64.getDecoder().decode(base64String);
    }

    /**
     * Obtain data according to the request.
     *
     * @param content request
     * @throws Exception {@link Exception}
     */
    
    public static byte[] aesEncryptUtil(byte[] content, final int mode) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        random.setSeed(DB_ENCRYPT_KEY.getBytes());
        keyGenerator.init(128, random);
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(mode, new SecretKeySpec(keyGenerator.generateKey().getEncoded(), "AES"));
        return cipher.doFinal(content);
    }

    /**
     * Obtain data according to the request.
     *
     * @param content content
     * @throws Exception {@link Exception}
     */
    public static String aesEncryptStr(byte[] content) throws Exception {
        return base64Encode(aesEncryptUtil(content, Cipher.ENCRYPT_MODE));
    }

    /**
     * Obtain data according to the request.
     * @param content content
     * @throws Exception {@link Exception}
     */
    public static String aesDecryptStr(String content) throws Exception {
        return StringUtils.isEmpty(content) ? null : new String(aesEncryptUtil(base64Decode(content), Cipher.DECRYPT_MODE));
    }

    public static void main(String[] args) {
        try {
            System.out.println(aesEncryptStr("root".getBytes()));
            System.out.println(aesDecryptStr("9XyVlFf6FKMF5DtdmMpd/Q=="));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}

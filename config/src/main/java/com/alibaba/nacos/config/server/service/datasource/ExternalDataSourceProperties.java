/*
 * Copyright 1999-2018 Alibaba Group Holding Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.alibaba.nacos.config.server.service.datasource;

import com.alibaba.nacos.common.utils.StringUtils;
import com.alibaba.nacos.config.server.utils.EncryptUtils;
import com.google.common.base.Preconditions;
import com.zaxxer.hikari.HikariDataSource;
import org.apache.commons.collections.CollectionUtils;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.core.env.Environment;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

import static com.alibaba.nacos.common.utils.CollectionUtils.getOrDefault;
import static com.alibaba.nacos.config.server.utils.LogUtil.FATAL_LOG;

/**
 * Properties of external DataSource.
 *
 * @author Nacos
 */
public class ExternalDataSourceProperties {

    private static final String JDBC_DRIVER_NAME = "com.mysql.cj.jdbc.Driver";
    private String jdbcDriverNameDM;

    public String getJdbcDriverNameDM() {
        return jdbcDriverNameDM;
    }

    public void setJdbcDriverNameDM(String jdbcDriverNameDM) {
        this.jdbcDriverNameDM = jdbcDriverNameDM;
    }

    private static final String TEST_QUERY = "SELECT 1";

    private static final String DB_ENCRYPT_PREFIX = "ENC(";

    private Integer num;

    private List<String> url = new ArrayList<>();

    private List<String> user = new ArrayList<>();

    private List<String> password = new ArrayList<>();

    public void setNum(Integer num) {
        this.num = num;
    }

    public void setUrl(List<String> url) {
        this.url = url;
    }

    public void setUser(List<String> user) {
        this.user = user;
    }

    public void setPassword(List<String> password) {
        this.password = password;
    }

    /**
     * Build serveral HikariDataSource.
     *
     * @param environment {@link Environment}
     * @param callback    Callback function when constructing data source
     * @return List of {@link HikariDataSource}
     */
    List<HikariDataSource> build(Environment environment, Callback<HikariDataSource> callback) {
        System.out.println("build");
        List<HikariDataSource> dataSources = new ArrayList<>();
        Binder.get(environment).bind("db", Bindable.ofInstance(this));
        Preconditions.checkArgument(Objects.nonNull(num), "db.num is null");
        Preconditions.checkArgument(CollectionUtils.isNotEmpty(user), "db.user or db.user.[index] is null");
        Preconditions.checkArgument(CollectionUtils.isNotEmpty(password), "db.password or db.password.[index] is null");
        for (int index = 0; index < num; index++) {
            int currentSize = index + 1;
            Preconditions.checkArgument(url.size() >= currentSize, "db.url.%s is null", index);
            DataSourcePoolProperties poolProperties = DataSourcePoolProperties.build(environment);
            poolProperties.setDriverClassName(JDBC_DRIVER_NAME);
            poolProperties.setJdbcUrl(url.get(index).trim());
            poolProperties.setUsername(getOrDefault(user, index, user.get(0)).trim());
            String pass = getOrDefault(password, index, password.get(0)).trim();
            //数据库密码解密
            try {
                if (pass.contains(DB_ENCRYPT_PREFIX)) {
                    poolProperties.setPassword(EncryptUtils.aesDecryptStr(pass.substring(4, pass.length() - 1)));
                } else {
                    poolProperties.setPassword(pass);
                }
            } catch (Exception e) {
                FATAL_LOG.error("datasource decrypt error", e);
            }
            HikariDataSource ds = poolProperties.getDataSource();
            ds.setConnectionTestQuery(TEST_QUERY);
            ds.setIdleTimeout(TimeUnit.MINUTES.toMillis(10L));
            ds.setConnectionTimeout(TimeUnit.SECONDS.toMillis(3L));
            System.out.println("#################################");
            System.out.println("jdbcDriverName=" + JDBC_DRIVER_NAME);
            System.out.println("jdbcDriverNameDM=" + jdbcDriverNameDM);
            if (StringUtils.isNotEmpty(jdbcDriverNameDM)) {
                // 增加其他数据库驱动的支持
                ds.setDriverClassName(jdbcDriverNameDM);
            } else {
                //默认使用mysql驱动
                ds.setDriverClassName(JDBC_DRIVER_NAME);
            }
            System.out.println("jdbcDriverName=" + JDBC_DRIVER_NAME);
            System.out.println("jdbcDriverName=" + jdbcDriverNameDM);
            System.out.println("dataSources=" + dataSources);
            System.out.println("#################################");
            dataSources.add(ds);
            callback.accept(ds);
        }
        Preconditions.checkArgument(CollectionUtils.isNotEmpty(dataSources), "no datasource available");
        return dataSources;
    }

    interface Callback<D> {

        /**
         * Perform custom logic.
         *
         * @param datasource dataSource.
         */
        void accept(D datasource);
    }
}

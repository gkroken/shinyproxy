/*
 * Skald
 *
 * Copyright (C) 2026 Gard Kroken
 *
 * Built on ShinyProxy, Copyright (C) 2016-2026 Open Analytics NV.
 *
 * ===========================================================================
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the Apache License as published by
 * The Apache Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * Apache License for more details.
 *
 * You should have received a copy of the Apache License
 * along with this program.  If not, see <http://www.apache.org/licenses/>
 */
package eu.openanalytics.shinyproxy.publisher.db;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.sql.DataSource;

/**
 * Defines the registry's {@link DataSource}.
 *
 * <p>This exists because {@code ContainerProxyApplication} excludes
 * {@code DataSourceAutoConfiguration} (line 93), so {@code spring.datasource.*} is inert on
 * its own: Spring Boot will never build a {@code DataSource} from it. Do not spend time
 * debugging why the properties "do nothing" — nothing reads them until this class does.
 *
 * <p>ContainerProxy's own usage-statistics collector is unaffected. {@code JDBCCollector}
 * constructs a {@code HikariDataSource} directly rather than exposing a bean, and is
 * configured separately under {@code proxy.usage-stats-url}.
 *
 * <p>The bean is conditional on {@code spring.datasource.url}. Without it the fork boots
 * exactly as upstream does, with no database and no registry — which is what keeps
 * ContainerProxy's own test suite, and any deployment not using the publishing layer,
 * working untouched. Spring Boot's Flyway auto-configuration is itself conditional on a
 * {@code DataSource} bean, so migrations are skipped in that case too.
 */
@Configuration
@ConditionalOnProperty(name = "spring.datasource.url")
public class DataSourceConfig {

    @Bean
    public DataSource dataSource(
        @Value("${spring.datasource.url}") String url,
        @Value("${spring.datasource.username:}") String username,
        @Value("${spring.datasource.password:}") String password,
        @Value("${spring.datasource.driver-class-name:org.postgresql.Driver}") String driverClassName) {

        return DataSourceBuilder.create()
            .url(url)
            .username(username)
            .password(password)
            .driverClassName(driverClassName)
            .build();
    }

}

import co.elastic.clients.elasticsearch.ElasticsearchAsyncClient;
import co.elastic.clients.elasticsearch.ElasticsearchClient;
import co.elastic.clients.elasticsearch._types.query_dsl.QueryBuilders;
import co.elastic.clients.elasticsearch._types.query_dsl.TermQuery;
import co.elastic.clients.elasticsearch.core.*;
import co.elastic.clients.elasticsearch.core.search.Hit;
import co.elastic.clients.json.jackson.JacksonJsonpMapper;
import co.elastic.clients.transport.ElasticsearchTransport;
import co.elastic.clients.transport.rest_client.RestClientTransport;
import org.apache.http.Header;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.nio.client.HttpAsyncClientBuilder;
import org.apache.http.message.BasicHeader;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.SSLContexts;
import org.elasticsearch.client.RestClient;
import org.elasticsearch.client.RestClientBuilder;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Base64;

public class ElasticsearchJava {

    private static ElasticsearchClient client = null;
    private static ElasticsearchAsyncClient asyncClient = null;

    private static synchronized void makeConnection() {
        final CredentialsProvider credentialsProvider =
                new BasicCredentialsProvider();
        credentialsProvider.setCredentials(AuthScope.ANY,
                new UsernamePasswordCredentials("elastic", "FW5S2hBXhCNZDZ7BX9O-"));

        RestClientBuilder builder = RestClient.builder(
                        new HttpHost("localhost", 9200))
                .setHttpClientConfigCallback(new RestClientBuilder.HttpClientConfigCallback() {
                    @Override
                    public HttpAsyncClientBuilder customizeHttpClient(
                            HttpAsyncClientBuilder httpClientBuilder) {
                        return httpClientBuilder
                                .setDefaultCredentialsProvider(credentialsProvider);
                    }
                });

        RestClient restClient = builder.build();

        // Create the transport with a Jackson mapper
        ElasticsearchTransport transport = new RestClientTransport(
                restClient, new JacksonJsonpMapper());

        try {
            // And create the API client
            client = new ElasticsearchClient(transport);
            asyncClient = new ElasticsearchAsyncClient(transport);
        } catch (Exception e) {
            System.out.println("Error in connecting Elasticsearch");
            e.printStackTrace();
        }
    }

    private static synchronized void makeConnection_https() throws CertificateException, IOException, NoSuchAlgorithmException,
            KeyStoreException, KeyManagementException {
        final CredentialsProvider credentialsProvider =
                new BasicCredentialsProvider();
        credentialsProvider.setCredentials(AuthScope.ANY,
                new UsernamePasswordCredentials("elastic", "FW5S2hBXhCNZDZ7BX9O-"));

        Path caCertificatePath = Paths.get("/Users/liuxg/test/elasticsearch-8.1.2/config/certs/http_ca.crt");
        CertificateFactory factory =
                CertificateFactory.getInstance("X.509");
        Certificate trustedCa;
        try (InputStream is = Files.newInputStream(caCertificatePath)) {
            trustedCa = factory.generateCertificate(is);
        }
        KeyStore trustStore = KeyStore.getInstance("pkcs12");
        trustStore.load(null, null);
        trustStore.setCertificateEntry("ca", trustedCa);
        SSLContextBuilder sslContextBuilder = SSLContexts.custom()
                .loadTrustMaterial(trustStore, null);
        final SSLContext sslContext = sslContextBuilder.build();

        RestClientBuilder builder = RestClient.builder(
                        new HttpHost("localhost", 9200, "https"))
                .setHttpClientConfigCallback(new RestClientBuilder.HttpClientConfigCallback() {
                    @Override
                    public HttpAsyncClientBuilder customizeHttpClient(
                            HttpAsyncClientBuilder httpClientBuilder) {
                        return httpClientBuilder.setSSLContext(sslContext)
                                .setDefaultCredentialsProvider(credentialsProvider);
                    }
                });

        RestClient restClient = builder.build();

        // Create the transport with a Jackson mapper
        ElasticsearchTransport transport = new RestClientTransport(
                restClient, new JacksonJsonpMapper());

        client = new ElasticsearchClient(transport);
        asyncClient = new ElasticsearchAsyncClient(transport);
    }

    private static synchronized void makeConnection_token() throws CertificateException, IOException, NoSuchAlgorithmException,
            KeyStoreException, KeyManagementException {
        Path caCertificatePath = Paths.get("/Users/liuxg/test/elasticsearch-8.1.2/config/certs/http_ca.crt");
        CertificateFactory factory =
                CertificateFactory.getInstance("X.509");
        Certificate trustedCa;
        try (InputStream is = Files.newInputStream(caCertificatePath)) {
            trustedCa = factory.generateCertificate(is);
        }
        KeyStore trustStore = KeyStore.getInstance("pkcs12");
        trustStore.load(null, null);
        trustStore.setCertificateEntry("ca", trustedCa);
        SSLContextBuilder sslContextBuilder = SSLContexts.custom()
                .loadTrustMaterial(trustStore, null);
        final SSLContext sslContext = sslContextBuilder.build();

        RestClientBuilder builder = RestClient.builder(
                        new HttpHost("localhost", 9200, "https"))
                .setHttpClientConfigCallback(new RestClientBuilder.HttpClientConfigCallback() {
                    @Override
                    public HttpAsyncClientBuilder customizeHttpClient(
                            HttpAsyncClientBuilder httpClientBuilder) {
                        return httpClientBuilder.setSSLContext(sslContext);
                    }
                });

//        String apiKeyId = "SY6uOoABwRrDJxOdlx78";
//        String apiKeySecret = "E8Ae8-FgScqT-nXCSBN0ew";
//        String apiKeyAuth =
//                Base64.getEncoder().encodeToString(
//                        (apiKeyId + ":" + apiKeySecret)
//                                .getBytes(StandardCharsets.UTF_8));
//        Header[] defaultHeaders =
//                new Header[]{new BasicHeader("Authorization",
//                        "ApiKey " + apiKeyAuth)};
//        builder.setDefaultHeaders(defaultHeaders);

        Header[] defaultHeaders =
                new Header[]{new BasicHeader("Authorization",
                        "ApiKey U1k2dU9vQUJ3UnJESnhPZGx4Nzg6RThBZTgtRmdTY3FULW5YQ1NCTjBldw==")};
        builder.setDefaultHeaders(defaultHeaders);

        RestClient restClient = builder.build();

        // Create the transport with a Jackson mapper
        ElasticsearchTransport transport = new RestClientTransport(
                restClient, new JacksonJsonpMapper());

        client = new ElasticsearchClient(transport);
        asyncClient = new ElasticsearchAsyncClient(transport);
    }

    public static void main(String[] args) throws IOException {
//        try {
//            makeConnection_https();
//        } catch (CertificateException e) {
//            e.printStackTrace();
//        } catch (NoSuchAlgorithmException e) {
//            e.printStackTrace();
//        } catch (KeyStoreException e) {
//            e.printStackTrace();
//        } catch (KeyManagementException e) {
//            e.printStackTrace();
//        }

        try {
            makeConnection_token();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (KeyManagementException e) {
            e.printStackTrace();
        }

        // Index data to an index products
        Product product = new Product("abc", "Bag", 42);

        IndexRequest<Object> indexRequest = new IndexRequest.Builder<>()
                .index("products")
                .id("abc")
                .document(product)
                .build();

        client.index(indexRequest);
//
//        Product product1 = new Product("efg", "Bag", 42);
//
//        client.index(builder -> builder
//                .index("products")
//                .id(product1.getId())
//                .document(product1)
//        );
//
//        // Search for a data
//        TermQuery query = QueryBuilders.term()
//                .field("name")
//                .value("bag")
//                .build();
//
//        SearchRequest request = new SearchRequest.Builder()
//                .index("products")
//                .query(query._toQuery())
//                .build();
//
//        SearchResponse<Product> search =
//                client.search(
//                        request,
//                        Product.class
//                );
//
//        for (Hit<Product> hit: search.hits().hits()) {
//            Product pd = hit.source();
//            System.out.println(pd);
//        }
//
//        SearchResponse<Product> search1 = client.search(s -> s
//                        .index("products")
//                        .query(q -> q
//                                .term(t -> t
//                                        .field("name")
//                                        .value(v -> v.stringValue("bag"))
//                                )),
//                Product.class);
//
//        for (Hit<Product> hit: search1.hits().hits()) {
//            Product pd = hit.source();
//            System.out.println(pd);
//        }
//
//        // Splitting complex DSL
//        TermQuery termQuery = TermQuery.of(t ->t.field("name").value("bag"));
//
//        SearchResponse<Product> search2 = client.search(s -> s
//                .index("products")
//                .query(termQuery._toQuery()),
//                Product.class
//        );
//
//        for (Hit<Product> hit: search2.hits().hits()) {
//            Product pd = hit.source();
//            System.out.println(pd);
//        }
//
//        // Creating aggregations
//        SearchResponse<Void> search3 = client.search( b-> b
//                .index("products")
//                .size(0)
//                .aggregations("price-histo", a -> a
//                        .histogram(h -> h
//                                .field("price")
//                                .interval(20.0)
//                        )
//                ),
//                Void.class
//        );
//
//        long firstBucketCount = search3.aggregations()
//                .get("price-histo")
//                .histogram()
//                .buckets().array()
//                .get(0)
//                .docCount();
//
//        System.out.println("doc count: " + firstBucketCount);
    }
}

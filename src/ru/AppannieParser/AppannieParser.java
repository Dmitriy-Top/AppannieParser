package ru.AppannieParser;


import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.DefaultProxyRoutePlanner;
import org.apache.http.message.BasicNameValuePair;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import javax.net.ssl.HttpsURLConnection;
import java.io.*;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;
import java.util.ArrayList;;
import java.util.List;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created by admin on 06.12.2016.
 */
public class AppannieParser {
    private String username;
    private String password;
    private String csrftoken;
    private String sessionId;
    private String aa_user_token;
    private String proxyIp;
    private Integer proxyPort;

    public AppannieParser(String username, String password, String proxyIp, Integer proxyPort) {
        this.username = username;
        this.password = password;
        this.proxyIp = proxyIp;
        this.proxyPort = proxyPort;
    }

    public Boolean Authorization() {
        Boolean isAuthorized = false;
        try {
            getCsrftokenAndSessionId(); //получаем сессию и токен
            if (this.sessionId != null & this.csrftoken != null) getUsertoken(); //получаем авторизацию (токен пользователя)
        } catch (IOException e) {
            e.printStackTrace();
        }

        if (this.sessionId != null & this.aa_user_token != null & this.csrftoken != null) isAuthorized = true;
        return isAuthorized;
    }

    private void getCsrftokenAndSessionId() throws IOException {
        String url = "https://www.appannie.com/account/login/";
        String requestProperty = "Host: www.appannie.com\n" +
                "Connection: keep-alive\n" +
                "Cache-Control: max-age=0\n" +
                "Upgrade-Insecure-Requests: 1\n" +
                "User-Agent: Mozilla/5.0 (Windows NT 6.3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36\n" +
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\n" +
                "DNT: 1\n" +
                "Accept-Encoding: gzip, deflate, sdch, br\n" +
                "Accept-Language: ru-RU,ru;q=0.8,en-US;q=0.6,en;q=0.4\n" +
                "Cookie: \n" +
                "X-Compress: null";
        Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(this.proxyIp, this.proxyPort));

        URL obj = new URL(url);
        HttpsURLConnection con = (HttpsURLConnection) obj.openConnection(proxy);
        con.setRequestMethod("GET");

        String[] requestPropertyArray = requestProperty.split("\\n");

        for (int i = 0; i < requestPropertyArray.length; i++) {
            String property = requestPropertyArray[i].split(":")[0];
            String volume = requestPropertyArray[i].split(":")[1].trim();
            con.setRequestProperty(property, volume);
        }

        if (con.getResponseCode() == 200) {
            this.csrftoken = con.getHeaderField(11).split(";")[0].split("csrftoken=")[1];
            this.sessionId = con.getHeaderField(12).split(";")[0].split("sessionId=")[1];
        } else {
            toLog("Bad response: code" + con.getResponseCode());
        }
    }

    private void getUsertoken() throws IOException {
        HttpPost httppost = new HttpPost("https://www.appannie.com/account/login/");
        String requestProperty = "Host: www.appannie.com\n" +
                "Cache-Control: max-age=0\n" +
                "Origin: https://www.appannie.com\n" +
                "Upgrade-Insecure-Requests: 1\n" +
                "User-Agent: Mozilla/5.0 (Windows NT 6.3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36\n" +
                "Content-Type: application/x-www-form-urlencoded\n" +
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\n" +
                "Accept-Encoding: gzip, deflate, br\n" +
                "Accept-Language: ru-RU,ru;q=0.8,en-US;q=0.6,en;q=0.4\n" +
                "Cookie: sessionId=" + this.sessionId + "; csrftoken=" + this.csrftoken + "\n";

        HttpHost proxy = new HttpHost(this.proxyIp, this.proxyPort, "http");

        DefaultProxyRoutePlanner routePlanner = new DefaultProxyRoutePlanner(proxy);
        CloseableHttpClient httpclient = HttpClients.custom()
                .setRoutePlanner(routePlanner)
                .build();

        List<NameValuePair> params = new ArrayList<NameValuePair>(2);

        params.add(new BasicNameValuePair("csrfmiddlewaretoken", this.csrftoken));
        params.add(new BasicNameValuePair("next", "/dashboard/home/"));
        params.add(new BasicNameValuePair("username", this.username));
        params.add(new BasicNameValuePair("password", this.password));

        httppost.setEntity(new UrlEncodedFormEntity(params, "UTF-8"));

        String[] requestPropertyArray = requestProperty.split("\\n");
        for (int i = 0; i < requestPropertyArray.length; i++) {
            String property = requestPropertyArray[i].split(": ")[0];
            String volume = requestPropertyArray[i].split(": ")[1].trim();
            httppost.addHeader(property, volume);
        }

        HttpResponse response = httpclient.execute(httppost);
        if (response.getStatusLine().getStatusCode() == 302) {
            this.sessionId = response.getAllHeaders()[9].getValue().split(";")[0].split("sessionId=")[1];
            this.aa_user_token = response.getAllHeaders()[10].getValue().split(";")[0].split("aa_user_token=")[1];
        } else {
            toLog("Bad response: code" + response.getStatusLine().getStatusCode());
        }
    }

    public TreeMap<String, Long> getKeyStat(String url) throws IOException {

        url = webUrlToAjaxUrl(url);
        if (url == null | this.sessionId == null | this.aa_user_token == null | this.csrftoken == null) { //проверяем наличе авторизации
            return null;
        }

        TreeMap<String, Long> resultMap = new TreeMap<>();
        String requestProperty = "Accept: application/json, text/plain, */*\n" + //представляемся авторизированным фронт-эндом
                "Accept-Encoding: gzip, deflate, sdch, br\n" +
                "Accept-Language: ru-RU,ru;q=0.8,en-US;q=0.6,en;q=0.4\n" +
                "Connection: keep-alive\n" +
                "DNT: 1\n" +
                "Host: www.appannie.com\n" +
                "Referer: https://www.appannie.com/apps/google-play/app/com.appzavr.sbb/keywords/\n" +
                "User-Agent: Mozilla/5.0 (Windows NT 6.3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36\n" +
                "X-Compress: null\n" +
                "X-NewRelic-ID: VwcPUFJXGwEBUlJSDgc=\n" +
                "X-Requested-With: XMLHttpRequest" + "\n" +
                "X-CSRFToken: " + this.csrftoken + "\n" +
                "Cookie: csrftoken=" + this.csrftoken + "; sessionId=" + this.sessionId + "; aa_user_token=" + this.aa_user_token + "\n";

        HttpHost proxy = new HttpHost(this.proxyIp, this.proxyPort, "http");
        DefaultProxyRoutePlanner routePlanner = new DefaultProxyRoutePlanner(proxy);
        CloseableHttpClient httpclient = HttpClients.custom()
                .setRoutePlanner(routePlanner)
                .build();
        HttpGet request = new HttpGet(url);

        String[] requestPropertyArray = requestProperty.split("\\n");

        for (int i = 0; i < requestPropertyArray.length; i++) {
            String property = requestPropertyArray[i].split(": ")[0];
            String volume = requestPropertyArray[i].split(": ")[1].trim();
            request.addHeader(property, volume);
        }

        HttpResponse response = httpclient.execute(request);
        HttpEntity entity = response.getEntity();
        String result = null;

        if (entity != null & response.getStatusLine().getStatusCode() == 200) {  //хо-хо мы поличили json с данными который предназначался для фронт-энда сервиса

            InputStream instream = entity.getContent();
            result = convertStreamToString(instream);
            instream.close();

            JSONParser parser = new JSONParser();

            try {
                Object obj = parser.parse(result);
                JSONObject jsonObj = (JSONObject) obj;
                for (int i = 0; i < 29; i++) { //сервис отдает по 30 ключевых слов, парсим json
                    JSONArray keywords = (JSONArray) jsonObj.get("keywords");
                    JSONObject wordArray = (JSONObject) keywords.get(i);
                    String word = (String) wordArray.get("word");
                    JSONArray rankVariation = (JSONArray) wordArray.get("rank_variation");
                    Long rank = (Long) rankVariation.get(0);
                    resultMap.put(word, rank);
                }
            } catch (ParseException e) {
                e.printStackTrace();
                toLog("Response not json");
            }

        } else {
            toLog("Bad response: code" + response.getStatusLine().getStatusCode());
        }


        return resultMap;
    }

    private static String convertStreamToString(InputStream is) { //конвертируем ответ сервера строку

        BufferedReader reader = new BufferedReader(new InputStreamReader(is));
        StringBuilder sb = new StringBuilder();

        String line = null;
        try {
            while ((line = reader.readLine()) != null) {
                sb.append(line + "\n");
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                is.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return sb.toString();
    }

    public String webUrlToAjaxUrl(String webUrl) { //преобразуем урл в ajax формат который используеться для общения между фронтом и бек-эндом
        String result = null;
        Pattern ptrnUrl = Pattern.compile("https:\\/\\/www\\.appannie\\.com\\/apps\\/\\S{3,11}\\/app\\/\\S*?\\/keywords\\/#countries=\\S{2,3}&device=.*?&start_date=\\d{4}-\\d{2}-\\d{2}&end_date=\\d{4}-\\d{2}-\\d{2}");
        Matcher mtchUrl = ptrnUrl.matcher(webUrl);
        if (mtchUrl.matches()) {
            webUrl = webUrl.replace("/apps/", "/ajax/apps/");
            webUrl = webUrl.replace("/keywords/#", "/keywords-rank/?_c=1&");
            webUrl = webUrl.replace("countries", "country");
            result = webUrl;
        }
        return result;
    }

    private void toLog(String massage) {
        System.out.println(massage); // заглушка лога
    }

}

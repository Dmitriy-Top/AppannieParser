package ru.AppannieParser;


import java.util.Map;
import java.util.TreeMap;

public class Main {

    public static void main(String[] args) throws Exception {
        TreeMap<String, Long> result = new TreeMap<>();

        AppannieParser parser = new AppannieParser("kqzerdmw@10mail.org", "kqzerdmw!1", "125.16.240.197", 8080); //login,pass,proxy ip,proxy port

        boolean IsAuthorized = parser.Authorization(); //симулируем авторизацию на сайте

        if (IsAuthorized) {
            result = parser.getKeyStat("https://www.appannie.com/apps/google-play/app/20600004774691/keywords/#countries=RU&device=&start_date=2016-10-21&end_date=2016-11-28"); //берем данный из ajax бек-энда представлясь фронтом
        }

        if (result != null) {
            for (Map.Entry<String, Long> entry : result.entrySet()) {
                System.out.println(entry.getKey() + ": " + entry.getValue());
            }
        }
    }
}

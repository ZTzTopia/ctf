---
title: Quiz
category: 
  - Mobile
  - "Reverse Engineering"
tags: 
completedDuringEvent: true
submitted: true
flag: INTIGRITI{4_R34l_m0b1l3_h4ck3RRRRR}
draft: true
---
## Scenario

> Can you solve all the questions?

By 0xM4hm0ud

## Solution

We can decompile the `.apk` file using JADX, and we can see the application Java code. Where the `MainActivity` is the entry point of the application. The `MainActivity` class has a method `playOnclick` which is called when the play button is clicked. The `playOnclick` method starts the `HomeActivity` activity.

```java
public void playOnclick(View view) {
    startActivity(new Intent(this, (Class<?>) HomeActivity.class));
}
```

The `HomeActivity` class has a method `onCreate` which is called when the activity is created. The `onCreate` method initializes the `SSLContext` and `SSLSocketFactory` and starts a new thread with `RunnableC0406b` class.

```
@Override // androidx.fragment.app.AbstractActivityC0157v, androidx.activity.AbstractActivityC0059n, p089v.AbstractActivityC1078f, android.app.Activity
public final void onCreate(Bundle bundle) {
    super.onCreate(bundle);
    setContentView(R.layout.activity_home);
    this.f1768y = (TextView) findViewById(R.id.equationText);
    this.f1769z = (TextView) findViewById(R.id.timerText);
    this.f1759A = (TextView) findViewById(R.id.questionCounterText);
    TrustManager[] trustManagerArr = {new C0408d()};
    try {
        SSLContext sSLContext = SSLContext.getInstance("TLS");
        try {
            sSLContext.init(null, trustManagerArr, new SecureRandom());
            C1043v c1043v = new C1043v();
            SSLSocketFactory socketFactory = sSLContext.getSocketFactory();
            X509TrustManager x509TrustManager = (X509TrustManager) trustManagerArr[0];
            AbstractC0562k.m1573C(socketFactory, "sslSocketFactory");
            AbstractC0562k.m1573C(x509TrustManager, "trustManager");
            if (AbstractC0562k.m1664m(socketFactory, c1043v.f4193n)) {
                AbstractC0562k.m1664m(x509TrustManager, c1043v.f4194o);
            }
            c1043v.f4193n = socketFactory;
            C0044l c0044l = C0044l.f159a;
            c1043v.f4199t = C0044l.f159a.mo101b(x509TrustManager);
            c1043v.f4194o = x509TrustManager;
            C0405a c0405a = new C0405a();
            AbstractC0562k.m1664m(c0405a, c1043v.f4197r);
            c1043v.f4197r = c0405a;
            this.f1766H = new C1044w(c1043v);
            this.f1765G = System.currentTimeMillis();
            new Thread(new RunnableC0406b(this, 2)).start();
        } catch (KeyManagementException e4) {
            throw new RuntimeException(e4);
        }
    } catch (NoSuchAlgorithmException e5) {
        throw new RuntimeException(e5);
    }
}
```

The `RunnableC0406b` class has a method `run` which is called when the thread is started. Because HomeActivity creates a new thread with `RunnableC0406b` with the `2` parameter, the `run` method will be called. The `run` method makes a POST request to the `https://quiz.ctf.intigriti.io/start` endpoint. The response of the request is a JSON object with the `game_id` and `equations` keys.

```
public /* synthetic */ RunnableC0406b(HomeActivity homeActivity, int i3) {
    this.f2025a = i3;
    this.f2026b = homeActivity;
}

@Override // java.lang.Runnable
public final void run() {
    Runnable runnableC0406b;
    int i3 = this.f2025a;
    HomeActivity homeActivity = this.f2026b;
    switch (i3) {
        case 0:
            int i4 = HomeActivity.f1758J;
            homeActivity.m1013v("Something went wrong! Try again!", false);
            break;
        case 1:
            int i5 = HomeActivity.f1758J;
            homeActivity.m1013v("Network error", false);
            break;
        case 2:
            int i6 = HomeActivity.f1758J;
            homeActivity.getClass();
            try {
                JSONObject jSONObject = new JSONObject();
                jSONObject.put("start_time", homeActivity.f1765G);
                C1046y c1046y = new C1046y();
                c1046y.m2495d("https://quiz.ctf.intigriti.io/start");
                String jSONObject2 = jSONObject.toString();
                Pattern pattern = C1042u.f4176c;
                c1046y.m2494c("POST", C1047z.m2496a(jSONObject2, C0248o.m811m("application/json")));
                C0744x m2492a = c1046y.m2492a();
                C1044w c1044w = homeActivity.f1766H;
                c1044w.getClass();
                C1019b0 m2606c = new C1116i(c1044w, m2492a, false).m2606c();
                int i7 = m2606c.f4057d;
                if (200 > i7 || i7 >= 300) {
                    runnableC0406b = new RunnableC0406b(homeActivity, 3);
                } else {
                    JSONObject jSONObject3 = new JSONObject(m2606c.f4060g.m2460x());
                    homeActivity.f1767I = jSONObject3.getString("game_id");
                    JSONArray jSONArray = jSONObject3.getJSONArray("equations");
                    String[] strArr = new String[jSONArray.length()];
                    for (int i8 = 0; i8 < jSONArray.length(); i8++) {
                        strArr[i8] = jSONArray.getString(i8);
                    }
                    runnableC0406b = new RunnableC0379q(homeActivity, 7, strArr);
                }
                homeActivity.runOnUiThread(runnableC0406b);
                break;
            } catch (Exception e4) {
                e4.printStackTrace();
                homeActivity.runOnUiThread(new RunnableC0406b(homeActivity, 4));
                return;
            }
        case 3:
            int i9 = HomeActivity.f1758J;
            homeActivity.getClass();
            Toast.makeText(homeActivity, "Error starting game!", 0).show();
            break;
        default:
            int i10 = HomeActivity.f1758J;
            homeActivity.getClass();
            Toast.makeText(homeActivity, "Network error!", 0).show();
            break;
    }
}
```

So if user clicks the submit? button, the `m1011t` method will be called. The `m1011t` method checks if the answer is correct, if it is correct, it will increment the `f1760B` based on expression result and increment the `f1761C` by 1. If `f1761C` is less than the length of `f1763E`, it will call the `m1012u` method. If `f1761C` is equal to the length of `f1763E`, it will creates a new thread with `RunnableC0379q` class with `5` parameter.

```
public final void m1011t(int i3) {
    int i4 = this.f1762D;
    if (i3 != i4) {
        m1013v("Wrong Answer!", false);
        return;
    }
    int i5 = this.f1760B + i4;
    this.f1760B = i5;
    int i6 = this.f1761C + 1;
    this.f1761C = i6;
    if (i6 < this.f1763E.length) {
        m1012u();
        return;
    }
    String valueOf = String.valueOf(i5 + this.f1765G);
    JSONObject jSONObject = new JSONObject();
    jSONObject.put("game_id", this.f1767I);
    jSONObject.put("end_time", valueOf);
    Executors.newSingleThreadExecutor().submit(new RunnableC0379q(this, 5, jSONObject));
}
```

The `RunnableC0379q` class has a method `run` which is called when the thread is started. Because HomeActivity creates a new thread with `RunnableC0379q` with the `5` parameter, the `run` method will be called. The `run` method makes a POST request to the `https://quiz.ctf.intigriti.io/submit` endpoint. The response of the request is a JSON object with the `result` key.

```
public /* synthetic */ RunnableC0379q(Object obj, int i3, Object obj2) {
    this.f1934a = i3;
    this.f1935b = obj;
    this.f1936c = obj2;
}

@Override // java.lang.Runnable
public final void run() {
    int i3 = this.f1934a;
    int i4 = 0;
    int i5 = 1;
    Object obj = this.f1936c;
    Object obj2 = this.f1935b;
    switch (i3) {
        case 0:
            ExecutorC0381r executorC0381r = (ExecutorC0381r) obj2;
            Runnable runnable = (Runnable) obj;
            executorC0381r.getClass();
            try {
                runnable.run();
                return;
            } finally {
                executorC0381r.m1131a();
            }
        case 1:
            ((AbstractC0562k) obj2).mo1702c1((Typeface) obj);
            return;
        case 2:
        default:
            HomeActivity homeActivity = (HomeActivity) obj2;
            String[] strArr = (String[]) obj;
            int i6 = HomeActivity.f1758J;
            homeActivity.getClass();
            homeActivity.f1764F = new CountDownTimerC0409e(homeActivity).start();
            if (strArr == null || strArr.length <= 0) {
                return;
            }
            homeActivity.f1763E = strArr;
            homeActivity.m1012u();
            return;
        case 3:
            AbstractC0986e abstractC0986e = (AbstractC0986e) obj;
            C0983b c0983b = AbstractC0984c.f3906a;
            AbstractC0562k.m1573C(abstractC0986e, "$violation");
            Log.e("FragmentStrictMode", "Policy violation with PENALTY_DEATH in " + ((String) obj2), abstractC0986e);
            throw abstractC0986e;
        case 4:
            Context context = (Context) obj;
            ((ProfileInstallerInitializer) obj2).getClass();
            (Build.VERSION.SDK_INT >= 28 ? AbstractC1090h.m2562a(Looper.getMainLooper()) : new Handler(Looper.getMainLooper())).postDelayed(new RunnableC0373n(context, i5), new Random().nextInt(Math.max(1000, 1)) + 5000);
            return;
        case 5:
            HomeActivity homeActivity2 = (HomeActivity) obj2;
            JSONObject jSONObject = (JSONObject) obj;
            int i7 = HomeActivity.f1758J;
            homeActivity2.getClass();
            try {
                C1046y c1046y = new C1046y();
                c1046y.m2495d("https://quiz.ctf.intigriti.io/submit");
                String jSONObject2 = jSONObject.toString();
                Pattern pattern = C1042u.f4176c;
                c1046y.m2494c("POST", C1047z.m2496a(jSONObject2, C0248o.m811m("application/json")));
                C0744x m2492a = c1046y.m2492a();
                C1044w c1044w = homeActivity2.f1766H;
                c1044w.getClass();
                C1019b0 m2606c = new C1116i(c1044w, m2492a, false).m2606c();
                int i8 = m2606c.f4057d;
                if (200 > i8 || i8 >= 300) {
                    homeActivity2.runOnUiThread(new RunnableC0406b(homeActivity2, i4));
                } else {
                    homeActivity2.runOnUiThread(new RunnableC0379q(homeActivity2, 6, m2606c.f4060g.m2460x()));
                }
                return;
            } catch (IOException e4) {
                e4.printStackTrace();
                homeActivity2.runOnUiThread(new RunnableC0406b(homeActivity2, i5));
                return;
            }
        case 6:
            HomeActivity homeActivity3 = (HomeActivity) obj2;
            String str = (String) obj;
            int i9 = HomeActivity.f1758J;
            homeActivity3.getClass();
            try {
                String string = new JSONObject(str).getString("result");
                if (string.contains("INTIGRITI{")) {
                    homeActivity3.m1013v(string, true);
                } else {
                    homeActivity3.m1013v("Time exceeded!", false);
                }
                return;
            } catch (JSONException unused) {
                homeActivity3.m1013v("Error parsing response!", false);
                return;
            }
    }
}
```

```py
import requests
import json
import time

url = 'https://quiz.ctf.intigriti.io/'
start_url = f'{url}/start'
submit_url = f'{url}/submit'

start_time = int(time.time() * 1000)

json_object = {
    'start_time': start_time
}

headers = {'Content-Type': 'application/json', 'User-Agent': 'okhttp/4.12.0'}
response = requests.post(start_url, data=json.dumps(json_object), headers=headers)
status_code = response.status_code

if 200 <= status_code < 300:
    print(f'Successfully started the game')
    
    response_json = response.json()
    game_id = response_json['game_id']
    equations = response_json['equations']

    equation_sum = 0
    for i in range(len(equations)):
        equation = equations[i]
        equation_sum += eval(equation)

    json_object = {
        'game_id': game_id,
        'end_time': str(start_time + equation_sum)
    }

    response = requests.post(submit_url, data=json.dumps(json_object), headers=headers)
    status_code = response.status_code
    if 200 <= status_code < 300:
        print(f'Successfully submitted the game')
        
        response_json = response.json()
        print(response_json)
```
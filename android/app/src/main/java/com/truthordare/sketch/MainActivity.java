package com.truthordare.sketch;

import android.graphics.Color;
import android.os.Build;
import android.os.Bundle;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.webkit.JavascriptInterface;
import androidx.activity.OnBackPressedCallback;
import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Configure Pure Black Status Bar with visible battery & network indicators (white icons)
        configureBlackStatusBar();

        // Setup native Javascript bridge for app exit
        setupNativeBridge();

        // Intercept Android hardware & gesture back button
        setupBackNavigation();
    }

    private void setupNativeBridge() {
        if (bridge != null && bridge.getWebView() != null) {
            bridge.getWebView().addJavascriptInterface(new Object() {
                @JavascriptInterface
                public void exitApp() {
                    runOnUiThread(() -> finishAffinity());
                }
            }, "AndroidBridge");
        }
    }

    private void setupBackNavigation() {
        getOnBackPressedDispatcher().addCallback(this, new OnBackPressedCallback(true) {
            @Override
            public void handleOnBackPressed() {
                if (bridge != null && bridge.getWebView() != null) {
                    bridge.getWebView().post(() -> {
                        bridge.getWebView().evaluateJavascript(
                            "if (typeof window.handleHardwareBackButton === 'function') {" +
                            "  window.handleHardwareBackButton();" +
                            "} else {" +
                            "  document.dispatchEvent(new Event('backbutton'));" +
                            "}",
                            null
                        );
                    });
                }
            }
        });
    }

    private void configureBlackStatusBar() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            Window window = getWindow();
            window.addFlags(WindowManager.LayoutParams.FLAG_DRAWS_SYSTEM_BAR_BACKGROUNDS);
            window.clearFlags(WindowManager.LayoutParams.FLAG_TRANSLUCENT_STATUS);
            window.setStatusBarColor(Color.BLACK);

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                View decorView = window.getDecorView();
                // Ensure SYSTEM_UI_FLAG_LIGHT_STATUS_BAR is cleared (false = white icons for battery/wifi on black bar)
                int flags = decorView.getSystemUiVisibility();
                flags &= ~View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR;
                decorView.setSystemUiVisibility(flags);
            }
        }
    }
}

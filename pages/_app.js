import React, { useRef } from "react";
import { ThemeProvider, CSSReset, theme } from "@chakra-ui/core";
import "isomorphic-unfetch";
import App from "next/app";
import Router from "next/router";
import LoadingBar from "react-top-loading-bar";
import auth0 from "config/auth0";
import Navigation from "components/navigation/navigation";
import { AuthProvider } from "contexts/auth-provider";
import fetcher from "utils/fetcher";
import colors from "utils/colors";

console.log(colors);
const CustomApp = ({ Component, pageProps, authenticated, user }) => {
  const ref = useRef(null);

  Router.onRouteChangeStart = () => {
    ref.current.continuousStart();
  };

  Router.onRouteChangeComplete = () => {
    ref.current.complete();
  };

  Router.onRouteChangeError = () => {
    ref.current.complete();
  };

  return (
    <AuthProvider authenticated={authenticated} user={user}>
      <ThemeProvider
        theme={{
          ...theme,
          fonts: {
            body: "DM Sans, sans-serif",
            heading: "DM Sans, serif",
            mono: "Menlo, monospace",
          },
        }}
      >
        <CSSReset />
        <LoadingBar color="#8AD3E0" ref={ref} />
        <Navigation />
        <Component {...pageProps} />
      </ThemeProvider>
    </AuthProvider>
  );
};

CustomApp.getInitialProps = async (context) => {
  const appProps = await App.getInitialProps(context);

  if (typeof window === "undefined") {
    const { req, res } = context.ctx;
    const session = await auth0.getSession(req);

    if (session && session.user) {
      const baseUrl = req ? `http://${req.headers.host}` : "";
      const dbUser = await fetcher(`${baseUrl}/api/profile`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ email: session.user.email }),
      });

      if (!dbUser.users) {
        res.writeHead(302, { Location: "/api/logout" });
        return res.end();
      }

      return {
        ...appProps,
        authenticated: true,
        user: { ...session.user, is_admin: dbUser.users.is_admin },
      };
    }

    return { ...appProps, authenticated: false, user: null };
  }

  return { ...appProps };
};

export function reportWebVitals({ id, name, label, value }) {
  window.gtag("event", name, {
    event_category:
      label === "web-vital" ? "Web Vitals" : "Next.js custom metric",
    value: Math.round(name === "CLS" ? value * 1000 : value), // values must be integers
    event_label: id, // id unique to current page load
    non_interaction: true, // avoids affecting bounce rate.
  });
}

export default CustomApp;

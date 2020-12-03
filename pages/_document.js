import React from "react";
import Document, { Html, Head, Main, NextScript } from "next/document";

export default class MyDocument extends Document {
  static async getInitialProps(ctx) {
    const initialProps = await Document.getInitialProps(ctx);
    return {
      ...initialProps,
    };
  }

  render() {
    return (
      <Html>
        <Head>
          <link
            href="https://fonts.googleapis.com/css2?family=DM+Sans:ital,wght@0,400;0,500;0,700;1,400;1,500;1,700&display=swap"
            rel="stylesheet"
          />
        </Head>
        <script
          async
          src="https://www.googletagmanager.com/gtag/js?id=G-RZZL7C4F5T"
        />
        <script
          // eslint-disable-next-line react/no-danger
          dangerouslySetInnerHTML={{
            __html: `window.dataLayer = window.dataLayer || [];
                    function gtag(){dataLayer.push(arguments);}
                    gtag('js', new Date());
                    gtag('config', 'G-RZZL7C4F5T');`,
          }}
        />
        <body>
          <Main />
          <NextScript />
        </body>
      </Html>
    );
  }
}

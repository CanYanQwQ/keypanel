#include <QCoreApplication>
#include <QDebug>
#include "cardkey/client.h"

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    Q_UNUSED(app);
    cardkey::ClientConfig config{
        QUrl(QString::fromUtf8(qEnvironmentVariable("CARDKEY_BASE_URL", "https://example.invalid"))),
        QString::fromUtf8(qEnvironmentVariable("CARDKEY_APP_ID", "ak_test_replace_me")),
        QString::fromUtf8(qEnvironmentVariable("CARDKEY_APP_SECRET", "sk_test_replace_me")),
    };
    qInfo() << "CardKey Qt client example configured for" << config.baseUrl;
    qInfo() << "No network call is made; never print AppSecret or complete card keys.";
    return 0;
}

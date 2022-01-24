// Copyright (c) 2011-2014 The Bitcoin Core developers
// Copyright (c) 2020-2021 The Vitae Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef VITAE_QT_VITAEADDRESSVALIDATOR_H
#define VITAE_QT_VITAEADDRESSVALIDATOR_H

#include <QValidator>

/** Base58 entry widget validator, checks for valid characters and
 * removes some whitespace.
 */
class VitaeAddressEntryValidator : public QValidator
{
    Q_OBJECT

public:
    explicit VitaeAddressEntryValidator(QObject *parent);

    State validate(QString &input, int &pos) const;
};

/** Vitae address widget validator, checks for a valid vitae address.
 */
class VitaeAddressCheckValidator : public QValidator
{
    Q_OBJECT

public:
    explicit VitaeAddressCheckValidator(QObject *parent);

    State validate(QString &input, int &pos) const;
};

#endif // VITAE_QT_VITAEADDRESSVALIDATOR_H

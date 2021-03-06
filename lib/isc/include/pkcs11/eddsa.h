/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#ifndef _EDDSA_H_
#define _EDDSA_H_ 1

#ifndef CKK_EDDSA
#ifdef PK11_SOFTHSMV2_FLAVOR
#define CKK_EDDSA 0x00008003UL
#endif /* ifdef PK11_SOFTHSMV2_FLAVOR */
#endif /* ifndef CKK_EDDSA */

#ifndef CKM_EDDSA_KEY_PAIR_GEN
#ifdef PK11_SOFTHSMV2_FLAVOR
#define CKM_EDDSA_KEY_PAIR_GEN 0x00009040UL
#endif /* ifdef PK11_SOFTHSMV2_FLAVOR */
#endif /* ifndef CKM_EDDSA_KEY_PAIR_GEN */

#ifndef CKM_EDDSA
#ifdef PK11_SOFTHSMV2_FLAVOR
#define CKM_EDDSA 0x00009041UL
#endif /* ifdef PK11_SOFTHSMV2_FLAVOR */
#endif /* ifndef CKM_EDDSA */

#endif /* _EDDSA_H_ */

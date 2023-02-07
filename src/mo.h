/* Unable to document using sphinx. The function pointer typedef confuses the sphinx extension */

/*
 * Copyright (C) 2023 Freie Universität Berlin
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#ifndef MO_H
#define MO_H

typedef uint8_t (*schc_mo_op_t)(
    struct schc_field *target_field, unsigned char *field_value, uint16_t field_offset
);

#endif /* !MO_H */

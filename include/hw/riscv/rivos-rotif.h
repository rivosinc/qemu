/*
 * Rivos Root-of-Trust "widget" including DOE
 *
 * Copyright (C) 2022 Rivos Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 or later, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef HW_RIVOS_ROTIF_H
#define HW_RIVOS_ROTIF_H

#include "qemu/osdep.h"
#include "qom/object.h"

#define TYPE_RIVOS_ROTIF "rivos-rot-if"
OBJECT_DECLARE_SIMPLE_TYPE(RivosRotIFState, RIVOS_ROTIF)

#define ROTIF_MMIO_MAIN     (0)
#define ROTIF_DOE_HOST      (1)
#define ROTIF_DOE_IRQ       (0)

#endif /* HW_RIVOS_ROTIF_H */

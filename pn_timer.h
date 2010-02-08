/**
 * Copyright (C) 2009 Felipe Contreras
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef PN_TIMER_H
#define PN_TIMER_H

#include <glib.h>

struct pn_timer {
    /** @todo implement our own GSource to allow time resetting. */
    guint id;
    guint interval;
    GSourceFunc function;
    gpointer data;
};

static inline struct pn_timer *
pn_timer_new(GSourceFunc function,
             gpointer data)
{
    struct pn_timer *timer;
    timer = g_new0(struct pn_timer, 1);
    timer->function = function;
    timer->data = data;
    return timer;
}

static inline void
pn_timer_free(struct pn_timer *timer)
{
    if (!timer)
        return;
    if (timer->id)
        g_source_remove(timer->id);
    g_free(timer);
}

static inline void
pn_timer_start(struct pn_timer *timer,
               guint interval)
{
    if (timer->id)
        g_source_remove(timer->id);
    timer->interval = interval;
    timer->id = g_timeout_add_seconds(timer->interval,
                                      timer->function,
                                      timer->data);
}

static inline void
pn_timer_restart(struct pn_timer *timer)
{
    if (timer->id)
        g_source_remove(timer->id);
    timer->id = g_timeout_add_seconds(timer->interval,
                                      timer->function,
                                      timer->data);
}

static inline void
pn_timer_cancel(struct pn_timer *timer)
{
    timer->id = 0;
}

static inline void
pn_timer_stop(struct pn_timer *timer)
{
    g_source_remove(timer->id);
    timer->id = 0;
}

#endif /* PN_TIMER_H */

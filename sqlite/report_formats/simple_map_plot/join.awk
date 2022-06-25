# Copyright (C) 2010-2018 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

# joins threat data to coordinatesbased on IP as key.

BEGIN   { FS=","
          countLocations = 0
          countHosts = 0
        }

NF == 4 { # hits locations.csv
          locations[$1, "lon"] = $2
          locations[$1, "lat"] = $3
          locations[$1, "comment"] = $4
          countLocations ++
        }

NF == 5 { # hits hosts.csv
          hosts[countHosts, "IP"] = $1
          hosts[countHosts, "high"] = $2
          hosts[countHosts, "medium"] = $3
          hosts[countHosts, "low"] = $4
          hosts[countHosts, "color"] = $5
          countHosts ++
        }

END     {
          for (i = 0;i < countHosts;i ++)
            {
              if (locations[hosts[i, "IP"], "lon"] != "")
                printf("%s,%s,%s,%s,%s,%s,%s,%s\n", hosts[i, "IP"],
                                     locations[hosts[i, "IP"], "lon"],
                                     locations[hosts[i, "IP"], "lat"],
                                     locations[hosts[i, "IP"], "comment"],
                                     hosts[i, "high"],
                                     hosts[i, "medium"],
                                     hosts[i, "low"],
                                     hosts[i, "color"])
              if (locations[hosts[i, "IP"]] == "127.0.0.1")
                printf ("%s,%s,%s,%s,%s,%s,%s,%s\n", hosts[i, "IP"],
                                     locations[hosts[i, "IP"], "lon"],
                                     locations[hosts[i, "IP"], "lat"],
                                     locations[hosts[i, "IP"], "comment"],
                                     "0", "0", "0", "white")
            }
        }

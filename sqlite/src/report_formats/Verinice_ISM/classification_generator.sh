#!/bin/sh
# Copyright (C) 2011-2018 Greenbone Networks GmbH
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

# Generate classification helpers for verinice

cat << EOF
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
  <xsl:template name="generate-tags">
    <xsl:choose>
EOF

for line in $(tail -n +2 "$1" | tr -d '\015') #remove CR
do
    CPE=$(echo $line | sed 's/;/,/g' | awk -F , '{print $1}')
    TAG=$(echo $line | sed 's/;/,/g' | awk -F , '{print $2}')
    echo "        <xsl:when test=\"contains(value, '${CPE}')\">"
    echo "          <xsl:text>${TAG}</xsl:text>"
    echo "        </xsl:when>"
done

cat << EOF
      <xsl:otherwise>
        <xsl:text>gsm_system_unkown</xsl:text>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>
</xsl:stylesheet>
EOF

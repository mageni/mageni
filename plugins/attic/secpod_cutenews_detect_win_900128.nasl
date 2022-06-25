##############################################################################
# OpenVAS Vulnerability Test
# Description: CuteNews Version Detection for Windows
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900128");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2020-04-02T11:36:28+0000");
  script_tag(name:"last_modification", value:"2020-04-03 10:09:42 +0000 (Fri, 03 Apr 2020)");
  script_tag(name:"creation_date", value:"2008-12-02 11:52:55 +0100 (Tue, 02 Dec 2008)");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"0.0");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_name("CuteNews Version Detection for Windows");

  script_tag(name:"summary", value:"Deprecated: This NVT has been replaced by NVT 'CuteNews Detection' (OID:
  1.3.6.1.4.1.25623.1.0.100105).

  This script find the CuteNews installed version of Windows.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"deprecated", value: TRUE);

  exit(0);
}

exit(66);

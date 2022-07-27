###############################################################################
# OpenVAS Vulnerability Test
#
# Dell KACE K1000 Systems Management Appliance (SMA) Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803734");
  script_version("2020-04-02T11:36:28+0000");
  script_tag(name:"last_modification", value:"2020-04-03 10:09:42 +0000 (Fri, 03 Apr 2020)");
  script_tag(name:"creation_date", value:"2013-08-12 19:47:34 +0530 (Mon, 12 Aug 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Dell KACE K1000 Systems Management Appliance (SMA) Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");

  script_tag(name:"summary", value:"Detection of Dell KACE K1000 Systems Management Appliance.

  The script sends a connection request to the server and attempts to extract the version number from the reply.

  This NVT has been replaced by NVT 'Quest KACE Systems Management Applicance (SMA) Detection'
  (OID: 1.3.6.1.4.1.25623.1.0.141135).");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"deprecated", value: TRUE);

  exit(0);
}

exit(66);

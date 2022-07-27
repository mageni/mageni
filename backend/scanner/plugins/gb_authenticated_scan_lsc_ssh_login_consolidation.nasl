# Copyright (C) 2017 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108162");
  script_version("2021-07-29T14:32:53+0000");
  script_tag(name:"last_modification", value:"2021-07-29 14:32:53 +0000 (Thu, 29 Jul 2021)");
  script_tag(name:"creation_date", value:"2017-10-17 10:31:00 +0200 (Tue, 17 Oct 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Authenticated Scan / LSC Info Consolidation (Linux/Unix SSH Login)");
  script_category(ACT_END);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gather-package-list.nasl", "ssh_login_failed.nasl", "global_settings.nasl");
  script_mandatory_keys("login/SSH/success");

  script_tag(name:"summary", value:"Consolidation and reporting of various technical information
  about authenticated scans / local security checks (LSC) via SSH for Linux/Unix targets.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit( 66 );
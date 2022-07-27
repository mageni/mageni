###############################################################################
# OpenVAS Vulnerability Test
#
# Siemens SIMATIC WinCC/Audit Viewer Version Detection (Windows)
#
# Authors:
# Michael Martin <michael.martin@greenbone.net>
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH, http//www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.107481");
  script_version("2020-04-02T11:36:28+0000");
  script_tag(name:"last_modification", value:"2020-04-03 10:09:42 +0000 (Fri, 03 Apr 2020)");
  script_tag(name:"creation_date", value:"2019-01-26 09:49:54 +0100 (Sat, 26 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Siemens SIMATIC WinCC/Audit Viewer Version Detection (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");

  script_tag(name:"summary", value:"Detects the installed version
  of Siemens SIMATIC WinCC/Audit Viewer for Windows

  This VT is a duplicate of the existing VT 'Siemens SIMATIC WinCC/Audit Viewer Version Detection (Windows)' (OID: 1.3.6.1.4.1.25623.1.0.107574).");

  script_xref(name:"URL", value:"https://w3.siemens.com/mcms/human-machine-interface/de/visualisierungssoftware/scada-wincc/wincc-optionen/wincc-audit/Seiten/Default.aspx");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

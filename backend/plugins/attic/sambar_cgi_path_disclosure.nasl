###############################################################################
# OpenVAS Vulnerability Test
#
# Sambar CGIs path disclosure
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2005 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11775");
  script_version("2020-04-02T11:36:28+0000");
  script_bugtraq_id(7207, 7208);
  script_cve_id("CVE-2003-1284");
  script_tag(name:"last_modification", value:"2020-04-03 10:09:42 +0000 (Fri, 03 Apr 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Sambar CGIs path disclosure");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Michel Arboi");
  script_family("Web application abuses");

  script_tag(name:"affected", value:"Sambar WebServer v5.3 and below.");

  script_tag(name:"solution", value:"Remove them.");

  script_tag(name:"summary", value:"environ.pl or testcgi.exe is installed. Those CGIs
  reveal the installation directory and some other information
  that could help an attacker.

  This NVT has been replaced by NVT 'Sambar default CGI info disclosure'
  (OID: 1.3.6.1.4.1.25623.1.0.80082).");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit( 66 );

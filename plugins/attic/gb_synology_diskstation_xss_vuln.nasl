###############################################################################
# OpenVAS Vulnerability Test
#
# Synology DiskStation Manager Cross-Site Scripting Vulnerability
#
# Authors:
# Deepednra Bapna <bdeepednra@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805391");
  script_version("2020-04-02T11:36:28+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2020-04-03 10:09:42 +0000 (Fri, 03 Apr 2020)");
  script_tag(name:"creation_date", value:"2015-05-28 13:19:38 +0530 (Thu, 28 May 2015)");
  script_tag(name:"qod", value:"50"); # Prone to false positives and doesn't match existing qod_types
  script_name("Synology DiskStation Manager Cross-Site Scripting Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Synology
  DiskStation Manager and is prone to xss vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"The error exist as input passed via,
  'compound' parameter to the 'entry.cgi' script is not validated before
  returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary HTML and script code in a user's browser session in the
  context of an affected site.");

  script_tag(name:"affected", value:"Synology DiskStation Manager 5.2-5565");

  script_tag(name:"solution", value:"Upgrade to the Synology DiskStation Manager
  5.2-5565 Update 1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/132050/synologydiskstation-xss.txt");
  script_xref(name:"URL", value:"https://www.securify.nl/advisory/SFY20150503/reflected_cross_site_scripting_in_synology_diskstation_manager.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");

  # This script was deprecated to avoid false positive,since the extra check is not possible.
  script_tag(name:"deprecated", value:TRUE);
  script_xref(name:"URL", value:"https://www.synology.com/en-global/releaseNote/DS214play");
  exit(0);
}

exit( 66 );

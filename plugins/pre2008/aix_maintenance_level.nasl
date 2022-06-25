###############################################################################
# OpenVAS Vulnerability Test
#
# AIX maintenance level
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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
  script_oid("1.3.6.1.4.1.25623.1.0.14611");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_name("AIX maintenance level");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("AIX Local Security Checks");
  script_dependencies("gather-package-list.nasl"); # The needed Host/AIX/oslevel kb key is never set here
  script_mandatory_keys("Host/AIX/oslevel");

  script_xref(name:"URL", value:"http://www-912.ibm.com/eserver/support/fixes/");

  script_tag(name:"solution", value:"You should install the mentioned patch for your system to be up-to-date.

  Please see the references for more information.");

  script_tag(name:"summary", value:"This plugin makes sure the remote AIX server is running
  the newest maintenance package.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

#here the list of last maintenance level
level4330 = 11;
level5100 = 8;
level5200 = 6;
level5300 = 2;

buf=get_kb_item("Host/AIX/oslevel");
if(!buf)
  exit(0);

v = split(buf, sep:"-",keep:FALSE);
if(isnull(v))
  exit(0);

osversion = int(v[0]);
level = int(chomp(v[1]));

if(osversion == 4330 && level < level4330) {
  report  = 'The remote host is missing an AIX maintenance packages.\n\n';
  report += "Maintenance level " + level + " is installed, last is " + level4330 + ".";
  security_message(port:0, data:report);
  exit(0);
}

if(osversion == 5100 && level < level5100) {
  report  = 'The remote host is missing an AIX maintenance packages.\n\n';
  report += "Maintenance level " + level + " is installed, last is " + level5100 + ".";
  security_message(port:0, data:report);
  exit(0);
}

if(osversion == 5200 && level < level5200) {
  report  = 'The remote host is missing an AIX maintenance packages.\n\n';
  report += "Maintenance level " + level + " is installed, last is " + level5200 + ".";
  security_message(port:0, data:report);
  exit(0);
}

if(osversion == 5300 && level < level5300) {
  report  = 'The remote host is missing an AIX maintenance packages.\n\n';
  report += "Maintenance level " + level + " is installed, last is " + level5300 + ".";
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
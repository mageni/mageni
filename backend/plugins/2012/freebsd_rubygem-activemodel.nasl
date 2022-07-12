###############################################################################
# OpenVAS Vulnerability Test
# $Id: freebsd_rubygem-activemodel.nasl 11762 2018-10-05 10:54:12Z cfischer $
#
# Auto generated from VID 748aa89f-d529-11e1-82ab-001fd0af1a4c
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisories, and are Copyright (c) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.71520");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_cve_id("CVE-2012-2660", "CVE-2012-2661");
  script_version("$Revision: 11762 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-08-10 03:22:17 -0400 (Fri, 10 Aug 2012)");
  script_name("FreeBSD Ports: rubygem-activemodel");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: rubygem-activemodel

CVE-2012-2660
actionpack/lib/action_dispatch/http/request.rb in Ruby on Rails before
3.0.13, 3.1.x before 3.1.5, and 3.2.x before 3.2.4 does not properly
consider differences in parameter handling between the Active Record
component and the Rack interface, which allows remote attackers to
bypass intended database-query restrictions and perform NULL checks
via a crafted request, as demonstrated by certain '[nil]' values, a
related issue to CVE-2012-2694.
CVE-2012-2661
The Active Record component in Ruby on Rails 3.0.x before 3.0.13,
3.1.x before 3.1.5, and 3.2.x before 3.2.4 does not properly implement
the passing of request data to a where method in an ActiveRecord
class, which allows remote attackers to conduct certain SQL injection
attacks via nested query parameters that leverage unintended
recursion, a related issue to CVE-2012-2695.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"https://groups.google.com/forum/?fromgroups#!topic/rubyonrails-security/8SA-M3as7A8");
  script_xref(name:"URL", value:"https://groups.google.com/forum/?fromgroups#!topic/rubyonrails-security/dUaiOOGWL1k");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/748aa89f-d529-11e1-82ab-001fd0af1a4c.html");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-bsd.inc");

vuln = FALSE;
txt = "";

bver = portver(pkg:"rubygem-activemodel");
if(!isnull(bver) && revcomp(a:bver, b:"3.2.4")<0) {
  txt += "Package rubygem-activemodel version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
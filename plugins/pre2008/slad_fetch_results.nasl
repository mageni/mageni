###############################################################################
# OpenVAS Vulnerability Test
# $Id: slad_fetch_results.nasl 11543 2018-09-21 20:25:26Z cfischer $
#
# Fetch results of SLAD queries from a remote machine
#
# Authors:
# Dirk Jagdmann
# Michael Wiegand
#
# Changes:
# Thomas Rotter
#
# Copyright:
# Copyright (c) 2005 Greenbone Networks GmbH
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
################################################################################

if(description) {
  script_oid("1.3.6.1.4.1.25623.1.0.90003");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11543 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-21 22:25:26 +0200 (Fri, 21 Sep 2018) $");
  script_tag(name:"creation_date", value:"2007-07-31 16:52:22 +0200 (Tue, 31 Jul 2007)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("SLAD Fetch Results");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Greenbone Networks GmbH");
  script_family("General");

  script_dependencies("find_service.nasl", "ssh_authorization.nasl");
  script_require_ports(22, "Services/ssh");
  script_require_keys("Secret/SSH/login");

  script_tag(name:"summary", value:"This script connects to SLAD on a remote host to fetch
the result from scripts started earlier.
To work properly, this script requires to be provided
with a valid SSH login by means of an SSH key with pass-
phrase if the SSH public key is passphrase-protected, or
a password to log in.");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"qod_type", value:"remote_active");
  exit(0);
}

exit(66);

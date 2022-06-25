# Copyright (C) 2020 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.853092");
  script_version("2020-04-07T12:33:10+0000");
  script_cve_id("CVE-2019-14751");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2020-04-08 11:51:46 +0000 (Wed, 08 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-01 03:03:19 +0000 (Wed, 01 Apr 2020)");
  script_name("openSUSE: Security Advisory for python-nltk (openSUSE-SU-2020:0436-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-03/msg00054.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-nltk'
  package(s) announced via the openSUSE-SU-2020:0436-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python-nltk fixes the following issues:

  Update to 3.4.5 (boo#1146427, CVE-2019-14751):

  * CVE-2019-14751: Fixed Zip slip vulnerability in downloader for the
  unlikely situation where a user configures their downloader to use a
  compromised server (boo#1146427)

  Update to 3.4.4:

  * fix bug in plot function (probability.py)

  * add improved PanLex Swadesh corpus reader

  * add Text.generate()

  * add QuadgramAssocMeasures

  * add SSP to tokenizers

  * return confidence of best tag from AveragedPerceptron

  * make plot methods return Axes objects

  * don't require list arguments to PositiveNaiveBayesClassifier.train

  * fix Tree classes to work with native Python copy library

  * fix inconsistency for NomBank

  * fix random seeding in LanguageModel.generate

  * fix ConditionalFreqDist mutation on tabulate/plot call

  * fix broken links in documentation

  * fix misc Wordnet issues

  * update installation instructions

  Version update to 3.4.1:

  * add chomsky_normal_form for CFGs

  * add meteor score

  * add minimum edit/Levenshtein distance based alignment function

  * allow access to collocation list via text.collocation_list()

  * support corenlp server options

  * drop support for Python 3.4

  * other minor fixes

  Update to v3.4:

  * Support Python 3.7

  * New Language Modeling package

  * Cistem Stemmer for German

  * Support Russian National Corpus incl POS tag model

  * Krippendorf Alpha inter-rater reliability test

  * Comprehensive code clean-ups

  * Switch continuous integration from Jenkins to Travis

  Updated to v3.3:

  * Support Python 3.6

  * New interface to CoreNLP

  * Support synset retrieval by sense key

  * Minor fixes to CoNLL Corpus Reader

  * AlignedSent

  * Fixed minor inconsistencies in APIs and API documentation

  * Better conformance to PEP8

  * Drop Moses Tokenizer (incompatible license)


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-436=1");

  script_tag(name:"affected", value:"'python-nltk' package(s) on openSUSE Leap 15.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap15.1") {

  if(!isnull(res = isrpmvuln(pkg:"python2-nltk", rpm:"python2-nltk~3.4.5~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-nltk", rpm:"python3-nltk~3.4.5~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
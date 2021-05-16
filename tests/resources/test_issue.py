import logging
import re
from time import sleep

from jira.exceptions import JIRAError
from tests.conftest import (
    JiraTestCase,
    broken_test,
    find_by_key,
    find_by_key_value,
    not_on_custom_jira_instance,
    rndstr,
)

LOGGER = logging.getLogger(__name__)


class IssueTests(JiraTestCase):
    def setUp(self):
        JiraTestCase.setUp(self)
        self.user_admin = self.jira.search_users(self.test_manager.CI_JIRA_ADMIN)[0]
        self.project_b = self.test_manager.project_b
        self.project_a = self.test_manager.project_a
        self.issue_1 = self.test_manager.project_b_issue1
        self.issue_2 = self.test_manager.project_b_issue2
        self.issue_3 = self.test_manager.project_b_issue3

    def test_issue(self):
        issue = self.jira.issue(self.issue_1)
        self.assertEqual(issue.key, self.issue_1)
        self.assertEqual(issue.fields.summary, "issue 1 from %s" % self.project_b)

    @broken_test(reason="disabled as it seems to be ignored by jira, returning all")
    def test_issue_field_limiting(self):
        issue = self.jira.issue(self.issue_2, fields="summary,comment")
        self.assertEqual(issue.fields.summary, "issue 2 from %s" % self.project_b)
        comment1 = self.jira.add_comment(issue, "First comment")
        comment2 = self.jira.add_comment(issue, "Second comment")
        comment3 = self.jira.add_comment(issue, "Third comment")
        self.jira.issue(self.issue_2, fields="summary,comment")
        LOGGER.warning(issue.raw["fields"])
        self.assertFalse(hasattr(issue.fields, "reporter"))
        self.assertFalse(hasattr(issue.fields, "progress"))
        comment1.delete()
        comment2.delete()
        comment3.delete()

    def test_issue_equal(self):
        issue1 = self.jira.issue(self.issue_1)
        issue2 = self.jira.issue(self.issue_2)
        issues = self.jira.search_issues("key=%s" % self.issue_1)
        self.assertTrue(issue1 is not None)
        self.assertTrue(issue1 == issues[0])
        self.assertFalse(issue2 == issues[0])

    def test_issue_expand(self):
        issue = self.jira.issue(self.issue_1, expand="editmeta,schema")
        self.assertTrue(hasattr(issue, "editmeta"))
        self.assertTrue(hasattr(issue, "schema"))
        # testing for changelog is not reliable because it may exist or not based on test order
        # self.assertFalse(hasattr(issue, 'changelog'))

    @not_on_custom_jira_instance
    def test_create_issue_with_fieldargs(self):
        issue = self.jira.create_issue(
            project=self.project_b,
            summary="Test issue created",
            description="foo description",
            issuetype={"name": "Bug"},
        )  # customfield_10022='XSS'
        self.assertEqual(issue.fields.summary, "Test issue created")
        self.assertEqual(issue.fields.description, "foo description")
        self.assertEqual(issue.fields.issuetype.name, "Bug")
        self.assertEqual(issue.fields.project.key, self.project_b)
        # self.assertEqual(issue.fields.customfield_10022, 'XSS')
        issue.delete()

    @not_on_custom_jira_instance
    def test_create_issue_with_fielddict(self):
        fields = {
            "project": {"key": self.project_b},
            "summary": "Issue created from field dict",
            "description": "Some new issue for test",
            "issuetype": {"name": "Bug"},
            # 'customfield_10022': 'XSS',
            "priority": {"name": "Major"},
        }
        issue = self.jira.create_issue(fields=fields)
        self.assertEqual(issue.fields.summary, "Issue created from field dict")
        self.assertEqual(issue.fields.description, "Some new issue for test")
        self.assertEqual(issue.fields.issuetype.name, "Bug")
        self.assertEqual(issue.fields.project.key, self.project_b)
        # self.assertEqual(issue.fields.customfield_10022, 'XSS')
        self.assertEqual(issue.fields.priority.name, "Major")
        issue.delete()

    @not_on_custom_jira_instance
    def test_create_issue_without_prefetch(self):
        issue = self.jira.create_issue(
            prefetch=False,
            project=self.project_b,
            summary="Test issue created",
            description="some details",
            issuetype={"name": "Bug"},
        )  # customfield_10022='XSS'

        assert hasattr(issue, "self")
        assert hasattr(issue, "raw")
        assert "fields" not in issue.raw
        issue.delete()

    @not_on_custom_jira_instance
    def test_create_issues(self):
        field_list = [
            {
                "project": {"key": self.project_b},
                "summary": "Issue created via bulk create #1",
                "description": "Some new issue for test",
                "issuetype": {"name": "Bug"},
                # 'customfield_10022': 'XSS',
                "priority": {"name": "Major"},
            },
            {
                "project": {"key": self.project_a},
                "issuetype": {"name": "Bug"},
                "summary": "Issue created via bulk create #2",
                "description": "Another new issue for bulk test",
                "priority": {"name": "Major"},
            },
        ]
        issues = self.jira.create_issues(field_list=field_list)
        self.assertEqual(len(issues), 2)
        self.assertIsNotNone(issues[0]["issue"], "the first issue has not been created")
        self.assertEqual(
            issues[0]["issue"].fields.summary, "Issue created via bulk create #1"
        )
        self.assertEqual(
            issues[0]["issue"].fields.description, "Some new issue for test"
        )
        self.assertEqual(issues[0]["issue"].fields.issuetype.name, "Bug")
        self.assertEqual(issues[0]["issue"].fields.project.key, self.project_b)
        self.assertEqual(issues[0]["issue"].fields.priority.name, "Major")
        self.assertIsNotNone(
            issues[1]["issue"], "the second issue has not been created"
        )
        self.assertEqual(
            issues[1]["issue"].fields.summary, "Issue created via bulk create #2"
        )
        self.assertEqual(
            issues[1]["issue"].fields.description, "Another new issue for bulk test"
        )
        self.assertEqual(issues[1]["issue"].fields.issuetype.name, "Bug")
        self.assertEqual(issues[1]["issue"].fields.project.key, self.project_a)
        self.assertEqual(issues[1]["issue"].fields.priority.name, "Major")
        for issue in issues:
            issue["issue"].delete()

    @not_on_custom_jira_instance
    def test_create_issues_one_failure(self):
        field_list = [
            {
                "project": {"key": self.project_b},
                "summary": "Issue created via bulk create #1",
                "description": "Some new issue for test",
                "issuetype": {"name": "Bug"},
                # 'customfield_10022': 'XSS',
                "priority": {"name": "Major"},
            },
            {
                "project": {"key": self.project_a},
                "issuetype": {"name": "InvalidIssueType"},
                "summary": "This issue will not succeed",
                "description": "Should not be seen.",
                "priority": {"name": "Blah"},
            },
            {
                "project": {"key": self.project_a},
                "issuetype": {"name": "Bug"},
                "summary": "However, this one will.",
                "description": "Should be seen.",
                "priority": {"name": "Major"},
            },
        ]
        issues = self.jira.create_issues(field_list=field_list)
        self.assertEqual(
            issues[0]["issue"].fields.summary, "Issue created via bulk create #1"
        )
        self.assertEqual(
            issues[0]["issue"].fields.description, "Some new issue for test"
        )
        self.assertEqual(issues[0]["issue"].fields.issuetype.name, "Bug")
        self.assertEqual(issues[0]["issue"].fields.project.key, self.project_b)
        self.assertEqual(issues[0]["issue"].fields.priority.name, "Major")
        self.assertEqual(issues[0]["error"], None)
        self.assertEqual(issues[1]["issue"], None)
        self.assertEqual(issues[1]["error"], {"issuetype": "issue type is required"})
        self.assertEqual(issues[1]["input_fields"], field_list[1])
        self.assertEqual(issues[2]["issue"].fields.summary, "However, this one will.")
        self.assertEqual(issues[2]["issue"].fields.description, "Should be seen.")
        self.assertEqual(issues[2]["issue"].fields.issuetype.name, "Bug")
        self.assertEqual(issues[2]["issue"].fields.project.key, self.project_a)
        self.assertEqual(issues[2]["issue"].fields.priority.name, "Major")
        self.assertEqual(issues[2]["error"], None)
        self.assertEqual(len(issues), 3)
        for issue in issues:
            if issue["issue"] is not None:
                issue["issue"].delete()

    @not_on_custom_jira_instance
    def test_create_issues_without_prefetch(self):
        field_list = [
            dict(
                project=self.project_b,
                summary="Test issue created",
                description="some details",
                issuetype={"name": "Bug"},
            ),
            dict(
                project=self.project_a,
                summary="Test issue #2",
                description="foo description",
                issuetype={"name": "Bug"},
            ),
        ]
        issues = self.jira.create_issues(field_list, prefetch=False)

        assert hasattr(issues[0]["issue"], "self")
        assert hasattr(issues[0]["issue"], "raw")
        assert hasattr(issues[1]["issue"], "self")
        assert hasattr(issues[1]["issue"], "raw")
        assert "fields" not in issues[0]["issue"].raw
        assert "fields" not in issues[1]["issue"].raw
        for issue in issues:
            issue["issue"].delete()

    @not_on_custom_jira_instance
    def test_update_with_fieldargs(self):
        issue = self.jira.create_issue(
            project=self.project_b,
            summary="Test issue for updating",
            description="Will be updated shortly",
            issuetype={"name": "Bug"},
        )
        # customfield_10022='XSS')
        issue.update(
            summary="Updated summary",
            description="Now updated",
            issuetype={"name": "Story"},
        )
        self.assertEqual(issue.fields.summary, "Updated summary")
        self.assertEqual(issue.fields.description, "Now updated")
        self.assertEqual(issue.fields.issuetype.name, "Story")
        # self.assertEqual(issue.fields.customfield_10022, 'XSS')
        self.assertEqual(issue.fields.project.key, self.project_b)
        issue.delete()

    @not_on_custom_jira_instance
    def test_update_with_fielddict(self):
        issue = self.jira.create_issue(
            project=self.project_b,
            summary="Test issue for updating",
            description="Will be updated shortly",
            issuetype={"name": "Bug"},
        )
        fields = {
            "summary": "Issue is updated",
            "description": "it sure is",
            "issuetype": {"name": "Story"},
            # 'customfield_10022': 'DOC',
            "priority": {"name": "Major"},
        }
        issue.update(fields=fields)
        self.assertEqual(issue.fields.summary, "Issue is updated")
        self.assertEqual(issue.fields.description, "it sure is")
        self.assertEqual(issue.fields.issuetype.name, "Story")
        # self.assertEqual(issue.fields.customfield_10022, 'DOC')
        self.assertEqual(issue.fields.priority.name, "Major")
        issue.delete()

    def test_update_with_label(self):
        issue = self.jira.create_issue(
            project=self.project_b,
            summary="Test issue for updating labels",
            description="Label testing",
            issuetype=self.test_manager.CI_JIRA_ISSUE,
        )

        labelarray = ["testLabel"]
        fields = {"labels": labelarray}

        issue.update(fields=fields)
        self.assertEqual(issue.fields.labels, ["testLabel"])

    def test_update_with_bad_label(self):
        issue = self.jira.create_issue(
            project=self.project_b,
            summary="Test issue for updating labels",
            description="Label testing",
            issuetype=self.test_manager.CI_JIRA_ISSUE,
        )

        issue.fields.labels.append("this should not work")

        fields = {"labels": issue.fields.labels}

        self.assertRaises(JIRAError, issue.update, fields=fields)

    @not_on_custom_jira_instance
    def test_update_with_notify_false(self):
        issue = self.jira.create_issue(
            project=self.project_b,
            summary="Test issue for updating",
            description="Will be updated shortly",
            issuetype={"name": "Bug"},
        )
        issue.update(notify=False, description="Now updated, but silently")
        self.assertEqual(issue.fields.description, "Now updated, but silently")
        issue.delete()

    def test_delete(self):
        issue = self.jira.create_issue(
            project=self.project_b,
            summary="Test issue created",
            description="Not long for this world",
            issuetype=self.test_manager.CI_JIRA_ISSUE,
        )
        key = issue.key
        issue.delete()
        self.assertRaises(JIRAError, self.jira.issue, key)

    @not_on_custom_jira_instance
    def test_createmeta(self):
        meta = self.jira.createmeta()
        proj = find_by_key(meta["projects"], self.project_b)
        # we assume that this project should allow at least one issue type
        self.assertGreaterEqual(len(proj["issuetypes"]), 1)

    @not_on_custom_jira_instance
    def test_createmeta_filter_by_projectkey_and_name(self):
        meta = self.jira.createmeta(projectKeys=self.project_b, issuetypeNames="Bug")
        self.assertEqual(len(meta["projects"]), 1)
        self.assertEqual(len(meta["projects"][0]["issuetypes"]), 1)

    @not_on_custom_jira_instance
    def test_createmeta_filter_by_projectkeys_and_name(self):
        meta = self.jira.createmeta(
            projectKeys=(self.project_a, self.project_b), issuetypeNames="Story"
        )
        self.assertEqual(len(meta["projects"]), 2)
        for project in meta["projects"]:
            self.assertEqual(len(project["issuetypes"]), 1)

    @not_on_custom_jira_instance
    def test_createmeta_filter_by_id(self):
        projects = self.jira.projects()
        proja = find_by_key_value(projects, self.project_a)
        projb = find_by_key_value(projects, self.project_b)
        issue_type_ids = dict()
        full_meta = self.jira.createmeta(projectIds=(proja.id, projb.id))
        for project in full_meta["projects"]:
            for issue_t in project["issuetypes"]:
                issue_t_id = issue_t["id"]
                val = issue_type_ids.get(issue_t_id)
                if val is None:
                    issue_type_ids[issue_t_id] = []
                issue_type_ids[issue_t_id].append([project["id"]])
        common_issue_ids = []
        for key, val in issue_type_ids.items():
            if len(val) == 2:
                common_issue_ids.append(key)
        self.assertNotEqual(len(common_issue_ids), 0)
        for_lookup_common_issue_ids = common_issue_ids
        if len(common_issue_ids) > 2:
            for_lookup_common_issue_ids = common_issue_ids[:-1]
        meta = self.jira.createmeta(
            projectIds=(proja.id, projb.id), issuetypeIds=for_lookup_common_issue_ids
        )
        self.assertEqual(len(meta["projects"]), 2)
        for project in meta["projects"]:
            self.assertEqual(
                len(project["issuetypes"]), len(for_lookup_common_issue_ids)
            )

    def test_createmeta_expand(self):
        # limit to SCR project so the call returns promptly
        meta = self.jira.createmeta(
            projectKeys=self.project_b, expand="projects.issuetypes.fields"
        )
        self.assertTrue("fields" in meta["projects"][0]["issuetypes"][0])

    def test_assign_issue(self):
        self.assertTrue(self.jira.assign_issue(self.issue_1, self.user_admin.name))
        self.assertEqual(
            self.jira.issue(self.issue_1).fields.assignee.name, self.user_admin.name
        )

    def test_assign_issue_with_issue_obj(self):
        issue = self.jira.issue(self.issue_1)
        x = self.jira.assign_issue(issue, self.user_admin.name)
        self.assertTrue(x)
        self.assertEqual(
            self.jira.issue(self.issue_1).fields.assignee.name, self.user_admin.name
        )

    def test_assign_to_bad_issue_raises(self):
        self.assertRaises(JIRAError, self.jira.assign_issue, "NOPE-1", "notauser")

    def test_comments(self):
        for issue in [self.issue_1, self.jira.issue(self.issue_2)]:
            self.jira.issue(issue)
            comment1 = self.jira.add_comment(issue, "First comment")
            comment2 = self.jira.add_comment(issue, "Second comment")
            comments = self.jira.comments(issue)
            assert comments[0].body == "First comment"
            assert comments[1].body == "Second comment"
            comment1.delete()
            comment2.delete()
            comments = self.jira.comments(issue)
            assert len(comments) == 0

    def test_add_comment(self):
        comment = self.jira.add_comment(
            self.issue_3,
            "a test comment!",
            visibility={"type": "role", "value": "Administrators"},
        )
        self.assertEqual(comment.body, "a test comment!")
        self.assertEqual(comment.visibility.type, "role")
        self.assertEqual(comment.visibility.value, "Administrators")
        comment.delete()

    def test_add_comment_with_issue_obj(self):
        issue = self.jira.issue(self.issue_3)
        comment = self.jira.add_comment(
            issue,
            "a new test comment!",
            visibility={"type": "role", "value": "Administrators"},
        )
        self.assertEqual(comment.body, "a new test comment!")
        self.assertEqual(comment.visibility.type, "role")
        self.assertEqual(comment.visibility.value, "Administrators")
        comment.delete()

    def test_update_comment(self):
        comment = self.jira.add_comment(self.issue_3, "updating soon!")
        comment.update(body="updated!")
        self.assertEqual(comment.body, "updated!")
        # self.assertEqual(comment.visibility.type, 'role')
        # self.assertEqual(comment.visibility.value, 'Administrators')
        comment.delete()

    def test_editmeta(self):
        expected_fields = {
            "assignee",
            "attachment",
            "comment",
            "components",
            "description",
            "fixVersions",
            "issuelinks",
            "labels",
            "summary",
        }
        for i in (self.issue_1, self.issue_2):
            meta = self.jira.editmeta(i)
            meta_field_set = set(meta["fields"].keys())
            self.assertEqual(
                meta_field_set.intersection(expected_fields), expected_fields
            )

    # Nothing from remote link works
    #    def test_remote_links(self):
    #        self.jira.add_remote_link ('ZTRAVISDEB-3', globalId='python-test:story.of.horse.riding',
    #        links = self.jira.remote_links('QA-44')
    #        self.assertEqual(len(links), 1)
    #        links = self.jira.remote_links('BULK-1')
    #        self.assertEqual(len(links), 0)
    #
    #    @broken_test(reason="temporary disabled")
    #    def test_remote_links_with_issue_obj(self):
    #        issue = self.jira.issue('QA-44')
    #        links = self.jira.remote_links(issue)
    #        self.assertEqual(len(links), 1)
    #        issue = self.jira.issue('BULK-1')
    #        links = self.jira.remote_links(issue)
    #        self.assertEqual(len(links), 0)
    #
    #    @broken_test(reason="temporary disabled")
    #    def test_remote_link(self):
    #        link = self.jira.remote_link('QA-44', '10000')
    #        self.assertEqual(link.id, 10000)
    #        self.assertTrue(hasattr(link, 'globalId'))
    #        self.assertTrue(hasattr(link, 'relationship'))
    #
    #    @broken_test(reason="temporary disabled")
    #    def test_remote_link_with_issue_obj(self):
    #        issue = self.jira.issue('QA-44')
    #        link = self.jira.remote_link(issue, '10000')
    #        self.assertEqual(link.id, 10000)
    #        self.assertTrue(hasattr(link, 'globalId'))
    #        self.assertTrue(hasattr(link, 'relationship'))
    #
    #    @broken_test(reason="temporary disabled")
    #    def test_add_remote_link(self):
    #        link = self.jira.add_remote_link('BULK-3', globalId='python-test:story.of.horse.riding',
    #                                         object={'url': 'http://google.com', 'title': 'googlicious!'},
    #                                         application={'name': 'far too silly', 'type': 'sketch'}, relationship='mousebending')
    # creation response doesn't include full remote link info, so we fetch it again using the new internal ID
    #        link = self.jira.remote_link('BULK-3', link.id)
    #        self.assertEqual(link.application.name, 'far too silly')
    #        self.assertEqual(link.application.type, 'sketch')
    #        self.assertEqual(link.object.url, 'http://google.com')
    #        self.assertEqual(link.object.title, 'googlicious!')
    #        self.assertEqual(link.relationship, 'mousebending')
    #        self.assertEqual(link.globalId, 'python-test:story.of.horse.riding')
    #
    #    @broken_test(reason="temporary disabled")
    #    def test_add_remote_link_with_issue_obj(self):
    #        issue = self.jira.issue('BULK-3')
    #        link = self.jira.add_remote_link(issue, globalId='python-test:story.of.horse.riding',
    #                                         object={'url': 'http://google.com', 'title': 'googlicious!'},
    #                                         application={'name': 'far too silly', 'type': 'sketch'}, relationship='mousebending')
    # creation response doesn't include full remote link info, so we fetch it again using the new internal ID
    #        link = self.jira.remote_link(issue, link.id)
    #        self.assertEqual(link.application.name, 'far too silly')
    #        self.assertEqual(link.application.type, 'sketch')
    #        self.assertEqual(link.object.url, 'http://google.com')
    #        self.assertEqual(link.object.title, 'googlicious!')
    #        self.assertEqual(link.relationship, 'mousebending')
    #        self.assertEqual(link.globalId, 'python-test:story.of.horse.riding')
    #
    #    @broken_test(reason="temporary disabled")
    #    def test_update_remote_link(self):
    #        link = self.jira.add_remote_link('BULK-3', globalId='python-test:story.of.horse.riding',
    #                                         object={'url': 'http://google.com', 'title': 'googlicious!'},
    #                                         application={'name': 'far too silly', 'type': 'sketch'}, relationship='mousebending')
    # creation response doesn't include full remote link info, so we fetch it again using the new internal ID
    #        link = self.jira.remote_link('BULK-3', link.id)
    #        link.update(object={'url': 'http://yahoo.com', 'title': 'yahoo stuff'}, globalId='python-test:updated.id',
    #                    relationship='cheesing')
    #        self.assertEqual(link.globalId, 'python-test:updated.id')
    #        self.assertEqual(link.relationship, 'cheesing')
    #        self.assertEqual(link.object.url, 'http://yahoo.com')
    #        self.assertEqual(link.object.title, 'yahoo stuff')
    #        link.delete()
    #
    #    @broken_test(reason="temporary disabled")
    #    def test_delete_remove_link(self):
    #        link = self.jira.add_remote_link('BULK-3', globalId='python-test:story.of.horse.riding',
    #                                         object={'url': 'http://google.com', 'title': 'googlicious!'},
    #                                         application={'name': 'far too silly', 'type': 'sketch'}, relationship='mousebending')
    #        _id = link.id
    #        link.delete()
    #        self.assertRaises(JIRAError, self.jira.remote_link, 'BULK-3', _id)

    def test_transitioning(self):
        # we check with both issue-as-string or issue-as-object
        transitions = []
        for issue in [self.issue_2, self.jira.issue(self.issue_2)]:
            transitions = self.jira.transitions(issue)
            self.assertTrue(transitions)
            self.assertTrue("id" in transitions[0])
            self.assertTrue("name" in transitions[0])

        self.assertTrue(transitions, msg="Expecting at least one transition")
        # we test getting a single transition
        transition = self.jira.transitions(self.issue_2, transitions[0]["id"])[0]
        self.assertDictEqual(transition, transitions[0])

        # we test the expand of fields
        transition = self.jira.transitions(
            self.issue_2, transitions[0]["id"], expand="transitions.fields"
        )[0]
        self.assertTrue("fields" in transition)

        # Testing of transition with field assignment is disabled now because default workflows do not have it.

        # self.jira.transition_issue(issue, transitions[0]['id'], assignee={'name': self.test_manager.CI_JIRA_ADMIN})
        # issue = self.jira.issue(issue.key)
        # self.assertEqual(issue.fields.assignee.name, self.test_manager.CI_JIRA_ADMIN)
        #
        # fields = {
        #     'assignee': {
        #         'name': self.test_manager.CI_JIRA_USER
        #     }
        # }
        # transitions = self.jira.transitions(issue.key)
        # self.assertTrue(transitions)  # any issue should have at least one transition available to it
        # transition_id = transitions[0]['id']
        #
        # self.jira.transition_issue(issue.key, transition_id, fields=fields)
        # issue = self.jira.issue(issue.key)
        # self.assertEqual(issue.fields.assignee.name, self.test_manager.CI_JIRA_USER)
        # self.assertEqual(issue.fields.status.id, transition_id)

    def test_votes(self):
        self.jira_normal.remove_vote(self.issue_1)
        # not checking the result on this
        votes = self.jira.votes(self.issue_1)
        self.assertEqual(votes.votes, 0)

        self.jira_normal.add_vote(self.issue_1)
        new_votes = self.jira.votes(self.issue_1)
        assert votes.votes + 1 == new_votes.votes

        self.jira_normal.remove_vote(self.issue_1)
        new_votes = self.jira.votes(self.issue_1)
        assert votes.votes == new_votes.votes

    def test_votes_with_issue_obj(self):
        issue = self.jira_normal.issue(self.issue_1)
        self.jira_normal.remove_vote(issue)
        # not checking the result on this
        votes = self.jira.votes(issue)
        self.assertEqual(votes.votes, 0)

        self.jira_normal.add_vote(issue)
        new_votes = self.jira.votes(issue)
        assert votes.votes + 1 == new_votes.votes

        self.jira_normal.remove_vote(issue)
        new_votes = self.jira.votes(issue)
        assert votes.votes == new_votes.votes

    def test_add_remove_watcher(self):

        # removing it in case it exists, so we know its state
        self.jira.remove_watcher(self.issue_1, self.test_manager.user_admin.key)
        init_watchers = self.jira.watchers(self.issue_1).watchCount

        # adding a new watcher
        self.jira.add_watcher(self.issue_1, self.test_manager.user_admin.key)
        self.assertEqual(self.jira.watchers(self.issue_1).watchCount, init_watchers + 1)

        # now we verify that remove does indeed remove watchers
        self.jira.remove_watcher(self.issue_1, self.test_manager.user_admin.key)
        new_watchers = self.jira.watchers(self.issue_1).watchCount
        self.assertEqual(init_watchers, new_watchers)

    @not_on_custom_jira_instance
    def test_agile(self):
        uniq = rndstr()
        board_name = "board-" + uniq
        sprint_name = "sprint-" + uniq

        b = self.jira.create_board(board_name, self.project_a)
        assert isinstance(b.id, int)

        s = self.jira.create_sprint(sprint_name, b.id)
        assert isinstance(s.id, int)
        assert s.name == sprint_name
        assert s.state == "FUTURE"

        self.jira.add_issues_to_sprint(s.id, [self.issue_1])

        sprint_field_name = "Sprint"
        sprint_field_id = [
            f["schema"]["customId"]
            for f in self.jira.fields()
            if f["name"] == sprint_field_name
        ][0]
        sprint_customfield = "customfield_" + str(sprint_field_id)

        updated_issue_1 = self.jira.issue(self.issue_1)
        serialised_sprint = getattr(updated_issue_1.fields, sprint_customfield)[0]

        # Too hard to serialise the sprint object. Performing simple regex match instead.
        assert re.search(r"\[id=" + str(s.id) + ",", serialised_sprint)

        # self.jira.add_issues_to_sprint(s.id, self.issue_2)

        # self.jira.rank(self.issue_2, self.issue_1)

        sleep(2)  # avoid https://travis-ci.org/pycontribs/jira/jobs/176561534#L516
        s.delete()

        sleep(2)
        b.delete()
        # self.jira.delete_board(b.id)

    def test_worklogs(self):
        worklog = self.jira.add_worklog(self.issue_1, "2h")
        worklogs = self.jira.worklogs(self.issue_1)
        self.assertEqual(len(worklogs), 1)
        worklog.delete()

    def test_worklogs_with_issue_obj(self):
        issue = self.jira.issue(self.issue_1)
        worklog = self.jira.add_worklog(issue, "2h")
        worklogs = self.jira.worklogs(issue)
        self.assertEqual(len(worklogs), 1)
        worklog.delete()

    def test_worklog(self):
        worklog = self.jira.add_worklog(self.issue_1, "1d 2h")
        new_worklog = self.jira.worklog(self.issue_1, str(worklog))
        self.assertEqual(new_worklog.author.name, self.test_manager.user_admin.name)
        self.assertEqual(new_worklog.timeSpent, "1d 2h")
        worklog.delete()

    def test_worklog_with_issue_obj(self):
        issue = self.jira.issue(self.issue_1)
        worklog = self.jira.add_worklog(issue, "1d 2h")
        new_worklog = self.jira.worklog(issue, str(worklog))
        self.assertEqual(new_worklog.author.name, self.test_manager.user_admin.name)
        self.assertEqual(new_worklog.timeSpent, "1d 2h")
        worklog.delete()

    def test_add_worklog(self):
        worklog_count = len(self.jira.worklogs(self.issue_2))
        worklog = self.jira.add_worklog(self.issue_2, "2h")
        self.assertIsNotNone(worklog)
        self.assertEqual(len(self.jira.worklogs(self.issue_2)), worklog_count + 1)
        worklog.delete()

    def test_add_worklog_with_issue_obj(self):
        issue = self.jira.issue(self.issue_2)
        worklog_count = len(self.jira.worklogs(issue))
        worklog = self.jira.add_worklog(issue, "2h")
        self.assertIsNotNone(worklog)
        self.assertEqual(len(self.jira.worklogs(issue)), worklog_count + 1)
        worklog.delete()

    def test_update_and_delete_worklog(self):
        worklog = self.jira.add_worklog(self.issue_3, "3h")
        issue = self.jira.issue(self.issue_3, fields="worklog,timetracking")
        worklog.update(comment="Updated!", timeSpent="2h")
        self.assertEqual(worklog.comment, "Updated!")
        # rem_estimate = issue.fields.timetracking.remainingEstimate
        self.assertEqual(worklog.timeSpent, "2h")
        issue = self.jira.issue(self.issue_3, fields="worklog,timetracking")
        self.assertEqual(issue.fields.timetracking.remainingEstimate, "1h")
        worklog.delete()
        issue = self.jira.issue(self.issue_3, fields="worklog,timetracking")
        self.assertEqual(issue.fields.timetracking.remainingEstimate, "3h")

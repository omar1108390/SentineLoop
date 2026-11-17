from evaluation.export_judge_sample import choose_sample


def test_human_label_sample_is_seeded_and_balanced_by_family():
    rows = [
        {"index": str(index), "family": family}
        for family in ("override", "indirect", "leak")
        for index in range(10)
    ]
    first = choose_sample(rows, 12, 17)
    second = choose_sample(rows, 12, 17)
    assert first == second
    assert len(first) == 12
    assert {
        family: sum(row["family"] == family for row in first)
        for family in ("override", "indirect", "leak")
    } == {"override": 4, "indirect": 4, "leak": 4}

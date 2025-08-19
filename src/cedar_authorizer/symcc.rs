mod test {
    use std::str::FromStr;

    use crate::cedar_authorizer::capture_writer;

    #[tokio::test]
    async fn test_symcc() {
        let cvc5 = cedar_policy_symcc::solver::LocalSolver::cvc5().unwrap();
        /*let cvc5_wrapped = cvc5.wrap(
            |w| cedar_policy_symcc::capture::CaptureWriter::new(w),
            |r| cedar_policy_symcc::capture::CaptureReader::new(r),
        );*/
        let mut symcc = cedar_policy_symcc::CedarSymCompiler::new(cvc5).unwrap();

        let reqenv = cedar_policy::RequestEnv::new(
            "k8s::User".parse().unwrap(),
            r#"k8s::Action::"get""#.parse().unwrap(),
            "core::pods".parse().unwrap(),
        );

        let object_selected_pset = include_str!("testfiles/object_selected.cedar").parse().unwrap();
        let is_authorized_pset = include_str!("testfiles/is_authorized.cedar").parse().unwrap();


        let (schema, _) = cedar_policy::Schema::from_cedarschema_str(include_str!("testfiles/simple.cedarschema")).unwrap();
        let symenv = cedar_policy_symcc::SymEnv::new(&schema, &reqenv).unwrap();
        let object_selected_wtpset = cedar_policy_symcc::WellTypedPolicies::from_policies(&object_selected_pset, &reqenv, &schema).unwrap();
        let is_authorized_wtpset = cedar_policy_symcc::WellTypedPolicies::from_policies(&is_authorized_pset, &reqenv, &schema).unwrap();
        let result = symcc.check_implies_with_counterexample(&object_selected_wtpset, &is_authorized_wtpset, &symenv).await.unwrap().unwrap();

        println!("{}", result.request.principal().map(|r| r.to_string()).unwrap_or("<none>".to_string()));
        println!("{}", result.request.action().map(|r| r.to_string()).unwrap_or("<none>".to_string()));
        println!("{}", result.request.resource().map(|r| r.to_string()).unwrap_or("<none>".to_string()));
        println!("{}", result.entities.to_dot_str());
        // println!("{}", String::from_utf8(capture_solver.writer.captured_data().to_vec()).unwrap());
        result.entities.write_to_json(std::fs::File::create_new("src/cedar_authorizer/testfiles/symcc_result.json").unwrap()).unwrap();
        assert!(false);
    }
}
require "spec"
require "../src/auth"

describe Result do
  it "keeps the error of a failed result" do
    result = Result(Int32).error("boom")

    result.is_ok?.should be_false
    result.error.should eq("boom")
  end

  it "is ok when built from a value" do
    Result.ok(1).is_ok?.should be_true
  end
end

describe "pam_conversation" do
  it "answers a hidden prompt with the password" do
    prompt = "Password: "
    message = LibPAM::PamMessage.new(msg_style: LibPAM::PAM_PROMPT_ECHO_OFF, msg: prompt.to_unsafe)
    messages = pointerof(message)
    responses = Pointer(LibPAM::PamResponse).null

    ret = pam_conversation(1, pointerof(messages), pointerof(responses), Box.box("s3cret"))

    ret.should eq(LibPAM::PAM_SUCCESS)
    String.new(responses.value.resp).should eq("s3cret")
    pam_free_responses(responses, 1)
  end

  it "refuses a visible prompt without leaking the password" do
    sink = IO::Memory.new
    Logger.sink = sink
    prompt = "OTP: "
    message = LibPAM::PamMessage.new(msg_style: LibPAM::PAM_PROMPT_ECHO_ON, msg: prompt.to_unsafe)
    messages = pointerof(message)
    responses = Pointer(LibPAM::PamResponse).null

    ret = pam_conversation(1, pointerof(messages), pointerof(responses), Box.box("s3cret"))

    ret.should eq(LibPAM::PAM_CONV_ERR)
    responses.null?.should be_true
    sink.to_s.should_not contain("s3cret")
  ensure
    Logger.reset_sink
  end
end

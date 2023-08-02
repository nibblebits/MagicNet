
/**
 * This is the extension that will be used in electron to bind a bridge between javascript
 * and our Magicnet decentralized network framework
 */

#include <nan.h>
#include <map>
#include <string>

extern "C"
{
#include "magicnet/magicnet.h"
}

std::map<int, void *> pointer_map;
int pointer_id = 0;

int LibMagicNetPushPointer(void *ptr)
{
  pointer_map[pointer_id] = ptr;
  pointer_id++;
  return pointer_id;
}

void *LibMagicNetGetPointer(int index)
{
  if (pointer_map.find(index) == pointer_map.end())
  {
    Nan::ThrowError("The index is not a pointer");
  }
  return pointer_map[index];
}

void LibMagicNetCreateProgram(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
  // validate and convert arguments from JavaScript...

  if (info.Length() < 1)
  {
    Nan::ThrowTypeError("Arity mismatch");
    return;
  }

  // Validate the type of the first argument.
  if (!info[0]->IsString())
  {
    Nan::ThrowTypeError("Argument must be a string");
    return;
  }

  v8::String::Utf8Value program_name(Nan::GetCurrentContext()->GetIsolate(), info[0]);
  struct magicnet_program *program = magicnet_program(*program_name);
  if (!program)
  {
    Nan::ThrowTypeError("Failed to create a new program instance is the magicnet server running");
  }
  int index = LibMagicNetPushPointer(program);

  // return the index to JavaScript...
  v8::Local<v8::Number> res_num = Nan::New(index);
  info.GetReturnValue().Set(res_num);
}

void LibMagicNet_Init(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
  if (info.Length() < 1)
  {
    Nan::ThrowTypeError("Arity mismatch");
    return;
  }

  // Validate the type of the first argument.
  if (!info[0]->IsNumber())
  {
    Nan::ThrowTypeError("Argument must be a number");
    return;
  }

  // Convert the first argument to a number
  int flags = info[0]->NumberValue(Nan::GetCurrentContext()).FromJust();

  // Initialize the magicnet library
  int res = magicnet_init(flags);
  v8::Local<v8::Number> res_num = Nan::New(res);
  info.GetReturnValue().Set(res_num);
}

void Init(v8::Local<v8::Object> exports)
{
  v8::Local<v8::FunctionTemplate> magicnetInitFunction = Nan::New<v8::FunctionTemplate>(LibMagicNet_Init);
  Nan::Set(exports, Nan::New("magicnet_init").ToLocalChecked(),
           Nan::GetFunction(magicnetInitFunction).ToLocalChecked());

 v8::Local<v8::FunctionTemplate> magicnetProgramFunction = Nan::New<v8::FunctionTemplate>(LibMagicNetCreateProgram);
  Nan::Set(exports, Nan::New("magicnet_program").ToLocalChecked(),
           Nan::GetFunction(magicnetProgramFunction).ToLocalChecked());

}

NODE_MODULE(magicnet, Init)
